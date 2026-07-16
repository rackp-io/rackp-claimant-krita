"""RACKP Claimant — Krita plugin UI and event hooks.

Thin Krita layer over the Krita-independent application core (app.ClaimantApp).
On each save it anchors the file to the Keeper; every 30 s it anchors the session
log; the dock drives assessment filing and mailbox-driven progress. All protocol
and transport behaviour lives in the core (identity / anchoring / claimant /
transport); this module only wires Krita events and Qt widgets to it.
"""
import json
import threading
from pathlib import Path

from krita import Extension, Krita, DockWidget, DockWidgetFactory, DockWidgetFactoryBase
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QListWidget, QListWidgetItem, QMessageBox,
    QFileDialog, QFrame,
)
from PyQt5.QtCore import Qt, QTimer, QThread, pyqtSignal

from . import settings
from .app import ClaimantApp
from .anchoring import DeliveryRejected
from .transport import TransportError
from .log_manager import SessionLog
from .assessment_dialog import AssessmentDialog

DOCKER_ID = "rackp_claimant_docker"
LOG_INTERVAL_MS = 30_000  # anchor the session-log hash every 30 s if it changed

# The application core is shared across background threads; anchoring must stay
# sequential (monotonic sequence_number), so every core operation runs under this
# lock. Building the core is cheap but done once and reused.
_app: ClaimantApp | None = None
_lock = threading.Lock()
_threads = []
_dock_instance = None


def _get_app() -> ClaimantApp:
    global _app
    if _app is None:
        _app = ClaimantApp()
    return _app


def _reset_app():
    """Drop the cached core so the next operation rebuilds it (e.g. URL change)."""
    global _app
    _app = None


class _Worker(QThread):
    """Runs a core operation off the UI thread, serialized under the global lock."""
    done = pyqtSignal(bool, str, object)  # ok, message, payload

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    def run(self):
        try:
            with _lock:
                ok, msg, payload = self._fn()
            self.done.emit(ok, msg, payload)
        except DeliveryRejected as e:
            self.done.emit(False, f"拒否: {e.reason}", None)
        except TransportError as e:
            self.done.emit(False, f"通信失敗: {e}", None)
        except Exception as e:  # noqa: BLE001 — surface any failure to the dock
            self.done.emit(False, f"{type(e).__name__}: {e}", None)


def _run(fn, on_done=None):
    t = _Worker(fn)
    if on_done:
        t.done.connect(on_done)
    _threads.append(t)
    t.finished.connect(lambda: _threads.remove(t) if t in _threads else None)
    t.start()


# ---------------------------------------------------------------------------
# Docker (side panel)
# ---------------------------------------------------------------------------

class RACKPDock(DockWidget):
    def __init__(self):
        global _dock_instance
        super().__init__()
        self.setWindowTitle("RACKP Claimant")
        self._config = settings.load()
        self._build_ui()
        _dock_instance = self

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setAlignment(Qt.AlignTop)

        status_row = QHBoxLayout()
        self._dot = QLabel("●")
        self._dot.setStyleSheet("color: gray; font-size: 14px;")
        self._status = QLabel("待機中")
        status_row.addWidget(self._dot)
        status_row.addWidget(self._status)
        status_row.addStretch()
        layout.addLayout(status_row)

        layout.addWidget(QLabel("Terminal ID:"))
        self._tid_value = QLineEdit(self._config.get("terminal_id") or "（未生成）")
        self._tid_value.setReadOnly(True)
        self._tid_value.setStyleSheet("font-size: 9px;")
        layout.addWidget(self._tid_value)

        layout.addWidget(QLabel("Keeper:"))
        self._keeper_url = QLineEdit(self._config.get("keeper_url", ""))
        self._keeper_url.editingFinished.connect(self._on_keeper_url_changed)
        layout.addWidget(self._keeper_url)

        self._seq_label = QLabel(f"アンカー数: {self._config.get('sequence_number', 0)}")
        layout.addWidget(self._seq_label)
        self._last_label = QLabel("最終アンカー: —")
        self._last_label.setWordWrap(True)
        layout.addWidget(self._last_label)

        self._log_label = QLabel("ログ: —")
        self._log_label.setStyleSheet("font-size: 9px;")
        self._log_label.setWordWrap(True)
        layout.addWidget(self._log_label)

        sep = QFrame()
        sep.setFrameShape(QFrame.HLine)
        sep.setStyleSheet("color: #555;")
        layout.addWidget(sep)

        layout.addWidget(QLabel("査定"))
        layout.addWidget(QLabel("Referee:"))
        self._referee_url = QLineEdit(self._config.get("referee_url", ""))
        self._referee_url.editingFinished.connect(self._on_referee_url_changed)
        layout.addWidget(self._referee_url)

        self._btn_new = QPushButton("新規査定依頼…")
        self._btn_new.clicked.connect(self._on_new_assessment)
        layout.addWidget(self._btn_new)

        layout.addWidget(QLabel("インシデント一覧:"))
        self._incident_list = QListWidget()
        self._incident_list.setFixedHeight(100)
        self._incident_list.itemSelectionChanged.connect(self._on_incident_selected)
        layout.addWidget(self._incident_list)
        self._refresh_incident_list()

        btn_row = QHBoxLayout()
        self._btn_poll = QPushButton("進捗を確認")
        self._btn_poll.clicked.connect(self._on_poll)
        btn_row.addWidget(self._btn_poll)

        self._btn_cert = QPushButton("証明書を保存")
        self._btn_cert.setEnabled(False)
        self._btn_cert.clicked.connect(self._on_save_certificate)
        btn_row.addWidget(self._btn_cert)
        layout.addLayout(btn_row)

        self.setWidget(root)

    # --- settings edits ----------------------------------------------------

    def _on_keeper_url_changed(self):
        self._config = settings.load()
        self._config["keeper_url"] = self._keeper_url.text().strip()
        settings.save(self._config)
        _reset_app()

    def _on_referee_url_changed(self):
        self._config = settings.load()
        self._config["referee_url"] = self._referee_url.text().strip()
        settings.save(self._config)
        _reset_app()

    # --- incident list -----------------------------------------------------

    def _refresh_incident_list(self):
        self._incident_list.clear()
        config = settings.load()
        for iid, info in reversed(list(config.get("incidents", {}).items())):
            dt = info.get("created_at", "")
            date = f"{dt[:10]} {dt[11:16]}" if len(dt) >= 16 else dt[:10]
            label = f"{date} | {iid[:8]}… | {info.get('status', '?')} | {info.get('description', '')[:25]}"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, iid)
            self._incident_list.addItem(item)

    def _on_incident_selected(self):
        iid = self._selected_incident_id()
        config = settings.load()
        has_result = bool(iid and config.get("incidents", {}).get(iid, {}).get("result"))
        self._btn_cert.setEnabled(has_result)

    def _selected_incident_id(self):
        items = self._incident_list.selectedItems()
        return items[0].data(Qt.UserRole) if items else None

    # --- assessment: file --------------------------------------------------

    def _on_new_assessment(self):
        doc = Krita.instance().activeDocument()
        filepath = doc.fileName() if doc else None
        dlg = AssessmentDialog(self, filepath=filepath)
        if dlg.exec_() != AssessmentDialog.Accepted:
            return
        actor_id, description, fp = dlg.actor_id(), dlg.description(), dlg.filepath()
        real_fp = fp if fp and fp != "（未保存）" else None

        def fn():
            incident_id = _get_app().file_assessment(description, real_fp, actor_id or None)
            return True, f"査定依頼を送信しました: {incident_id[:8]}…", None

        self._btn_new.setEnabled(False)
        self._set_status(True, "査定依頼を送信中…")
        _run(fn, self._on_assessment_done)

    def _on_assessment_done(self, ok, msg, _payload):
        self._btn_new.setEnabled(True)
        self._set_status(ok, msg)
        self._refresh_incident_list()

    # --- assessment: poll mailbox (evidence query / result) ----------------

    def _on_poll(self):
        def fn():
            notes = _get_app().poll()
            return True, ("　".join(notes) if notes else "新しい通知はありません"), None

        self._btn_poll.setEnabled(False)
        self._set_status(True, "Keeper メールボックスを確認中…")
        _run(fn, self._on_poll_done)

    def _on_poll_done(self, ok, msg, _payload):
        self._btn_poll.setEnabled(True)
        self._set_status(ok, msg)
        self._refresh_incident_list()
        iid = self._selected_incident_id()
        if not iid:
            return
        result = settings.load().get("incidents", {}).get(iid, {}).get("result")
        if result:
            self._show_result(result)

    def _show_result(self, result: dict):
        v = result.get("assessment", {})
        fault = v.get("fault", {})
        es = v.get("evidence_sufficiency", {})
        if v:
            text = (
                f"assessment_status: {es.get('assessment_status', '?')}\n"
                f"actor_fault:    {fault.get('actor_fault', '?')}\n"
                f"claimant_fault: {fault.get('claimant_fault', '?')}\n"
                f"confidence:     {fault.get('confidence', '?')}\n"
                f"appeal_deadline: {result.get('additional_appeal_limit_datetime', '—')}\n\n"
                f"factual_findings:\n{v.get('factual_findings', '')}"
            )
        else:  # POH_CERTIFICATE
            prov = result.get("provenance", {})
            text = (
                f"POH_CERTIFICATE\n"
                f"human_ratio: {prov.get('human_ratio', '?')}\n"
                f"ai_ratio:    {prov.get('ai_ratio', '?')}\n"
                f"confidence:  {prov.get('confidence_level', '?')}"
            )
        QMessageBox.information(self, "査定結果", text)

    # --- certificate: save the received result -----------------------------

    def _on_save_certificate(self):
        iid = self._selected_incident_id()
        if not iid:
            return
        result = settings.load().get("incidents", {}).get(iid, {}).get("result")
        if not result:
            self._set_status(False, "保存できる査定結果がありません")
            return
        save_path, _ = QFileDialog.getSaveFileName(
            self, "証明書の保存先", str(Path.home() / f"rackp_cert_{iid[:8]}.json"),
            "JSON Files (*.json);;All Files (*)",
        )
        if not save_path:
            return
        try:
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            self._set_status(True, f"証明書を保存しました: {save_path}")
            QMessageBox.information(self, "証明書", f"保存しました:\n{save_path}")
        except Exception as e:  # noqa: BLE001
            self._set_status(False, f"保存エラー: {e}")

    # --- status ------------------------------------------------------------

    def _set_status(self, ok: bool, msg: str):
        self._dot.setStyleSheet(f'color: {"green" if ok else "red"}; font-size: 14px;')
        self._status.setText(msg)
        self._config = settings.load()
        self._tid_value.setText(self._config.get("terminal_id") or "（未生成）")
        self._seq_label.setText(f"アンカー数: {self._config.get('sequence_number', 0)}")
        self._last_label.setText(f"最終: {msg}")

    def set_log_path(self, path: str):
        self._log_label.setText(f"ログ: {path}")

    def canvasChanged(self, canvas):
        pass


# ---------------------------------------------------------------------------
# Extension
# ---------------------------------------------------------------------------

class RACKPClaimant(Extension):
    def __init__(self, parent):
        super().__init__(parent)
        self._session_log: SessionLog | None = None
        self._timer: QTimer | None = None
        self._last_anchored_hash: str | None = None

    def setup(self):
        app = _get_app()  # builds identity on first run
        self._session_log = SessionLog(app.terminal_id)

        def fn():
            app.session_start()
            return True, "SESSION_START anchored", None

        def on_session(ok, msg, _payload):
            if _dock_instance:
                _dock_instance._set_status(ok, msg)
                _dock_instance.set_log_path(str(self._session_log.path))

        _run(fn, on_session)

        self._timer = QTimer()
        self._timer.setInterval(LOG_INTERVAL_MS)
        self._timer.timeout.connect(self._on_timer)
        self._timer.start()

        notifier = Krita.instance().notifier()
        notifier.imageSaved.connect(self._on_image_saved)
        notifier.imageCreated.connect(self._on_image_created)
        notifier.imageClosed.connect(self._on_image_closed)

    def createActions(self, window):
        pass

    def _on_timer(self):
        if not self._session_log:
            return
        doc = Krita.instance().activeDocument()
        if doc and doc.modified():
            self._session_log.record("modified", document=doc.fileName() or "(unsaved)")
        log_hash = self._session_log.hash()
        if log_hash == self._last_anchored_hash:
            return
        self._last_anchored_hash = log_hash

        def fn():
            rec = _get_app().anchor_log(log_hash)
            return True, f"log anchored seq={rec.sequence_number}", None

        def on_done(ok, msg, _payload):
            if _dock_instance:
                _dock_instance._set_status(ok, msg)

        _run(fn, on_done)

    def _on_image_saved(self, filename: str):
        if self._session_log:
            self._session_log.record("saved", document=filename)

        def fn():
            rec = _get_app().anchor_file(filename)
            return True, f"saved anchor seq={rec.sequence_number}", None

        def on_done(ok, msg, _payload):
            if _dock_instance:
                _dock_instance._set_status(ok, msg)

        _run(fn, on_done)

    def _on_image_created(self, doc):
        if self._session_log and doc:
            name = doc if isinstance(doc, str) else (doc.fileName() or "(unsaved)")
            self._session_log.record("created", document=name)

    def _on_image_closed(self, doc):
        if self._session_log and doc:
            name = doc if isinstance(doc, str) else (doc.fileName() or "(unsaved)")
            self._session_log.record("closed", document=name)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

Krita.instance().addExtension(RACKPClaimant(Krita.instance()))
Krita.instance().addDockWidgetFactory(
    DockWidgetFactory(DOCKER_ID, DockWidgetFactoryBase.DockRight, RACKPDock)
)
