"""
Query dialog for opening a new assessment.

Two request kinds share one ASSESSMENT_REQUEST (RFC-0001 §8: PoHI reuses the
generic message with actor_id omitted). The radio group makes that fork
explicit — it changes only which fields are shown; the message the plugin
sends is identical to before (actor_id set vs. omitted).
"""
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QLabel,
    QLineEdit, QTextEdit, QDialogButtonBox, QRadioButton, QButtonGroup,
)

from . import settings


class AssessmentDialog(QDialog):
    def __init__(self, parent=None, filepath: str = None):
        super().__init__(parent)
        self.setWindowTitle('新規査定依頼')
        self.setMinimumWidth(400)
        self._filepath = filepath or '（未保存）'
        self._build_ui()
        self._on_kind_changed()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # 依頼の種類（PoHI は Actor 不在の査定 — §8）
        layout.addWidget(QLabel('依頼の種類:'))
        self._kind_assessment = QRadioButton('査定依頼（相手 Actor がいる事案）')
        self._kind_pohi = QRadioButton('人間関与証明 PoHI（この作品を単独で証明）')
        self._kind_assessment.setChecked(True)
        self._kind_group = QButtonGroup(self)
        self._kind_group.addButton(self._kind_assessment)
        self._kind_group.addButton(self._kind_pohi)
        self._kind_assessment.toggled.connect(self._on_kind_changed)
        layout.addWidget(self._kind_assessment)
        layout.addWidget(self._kind_pohi)

        # 対象ファイル（読み取り専用）
        layout.addWidget(QLabel('対象ファイル:'))
        self._file_label = QLineEdit(self._filepath)
        self._file_label.setReadOnly(True)
        self._file_label.setStyleSheet('color: gray; font-size: 9px;')
        layout.addWidget(self._file_label)

        # ファイルのアンカー情報
        config = settings.load()
        file_anchor = config.get('file_anchors', {}).get(self._filepath)
        if file_anchor:
            count = file_anchor.get('anchor_count', 1)
            ts = file_anchor.get('timestamp', '')
            last = f"{ts[:10]} {ts[11:16]}" if len(ts) >= 16 else ts
            anchor_info = f"アンカー回数: {count}回　最終: {last}"
            color = 'green'
        else:
            anchor_info = "このファイルのアンカーはまだありません。先に保存してください。"
            color = 'orange'
        anchor_label = QLabel(anchor_info)
        anchor_label.setStyleSheet(f'color: {color}; font-size: 9px;')
        layout.addWidget(anchor_label)

        # Actor ID（査定依頼のときだけ表示）
        self._actor_label = QLabel('Actor の Terminal ID（相手AIのUUID）:')
        layout.addWidget(self._actor_label)
        self._actor_id = QLineEdit()
        self._actor_id.setPlaceholderText('相手 AI の Terminal ID を入力')
        layout.addWidget(self._actor_id)

        # Description
        self._desc_label = QLabel('事案の説明:')
        layout.addWidget(self._desc_label)
        self._description = QTextEdit()
        self._description.setFixedHeight(100)
        layout.addWidget(self._description)

        # Note（種類に応じて差し替え）
        self._note = QLabel()
        self._note.setStyleSheet('color: gray; font-size: 9px;')
        self._note.setWordWrap(True)
        layout.addWidget(self._note)

        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _is_pohi(self) -> bool:
        return self._kind_pohi.isChecked()

    def _on_kind_changed(self, *_):
        pohi = self._is_pohi()
        # PoHI は Actor 不在: Actor 欄を隠す。
        self._actor_label.setVisible(not pohi)
        self._actor_id.setVisible(not pohi)
        if pohi:
            self._desc_label.setText('作品の説明:')
            self._description.setPlaceholderText('何を制作したか、証明したい作品の内容を記述してください')
            self._note.setText('※ この作品のアンカー列（制作過程の記録）の連続性から人間関与度を'
                               '評価し、POH_CERTIFICATE を発行します（RFC-0001 §8）。')
        else:
            self._desc_label.setText('事案の説明:')
            self._description.setPlaceholderText('何が起きたか、何を申立てるかを記述してください')
            self._note.setText('※ 現在のセッションログの最新アンカーを証拠として自動提出します。')

    def _on_accept(self):
        if not self._description.toPlainText().strip():
            self._description.setStyleSheet('border: 1px solid red;')
            return
        self.accept()

    def actor_id(self) -> str:
        # PoHI は Actor 不在 (§8): 空文字を返し、呼び出し側で actor_id 省略に変換される。
        if self._is_pohi():
            return ''
        return self._actor_id.text().strip()

    def description(self) -> str:
        return self._description.toPlainText().strip()

    def filepath(self) -> str:
        return self._filepath
