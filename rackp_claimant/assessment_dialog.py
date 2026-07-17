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
        self.setWindowTitle('New Assessment Request')
        self.setMinimumWidth(400)
        self._filepath = filepath or '(unsaved)'
        self._build_ui()
        self._on_kind_changed()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        # Request kind (PoHI is an assessment without an Actor — §8)
        layout.addWidget(QLabel('Request type:'))
        self._kind_assessment = QRadioButton('Assessment (an incident with a counterparty Actor)')
        self._kind_pohi = QRadioButton('Proof of Human Involvement — PoHI (attest this work on its own)')
        self._kind_assessment.setChecked(True)
        self._kind_group = QButtonGroup(self)
        self._kind_group.addButton(self._kind_assessment)
        self._kind_group.addButton(self._kind_pohi)
        self._kind_assessment.toggled.connect(self._on_kind_changed)
        layout.addWidget(self._kind_assessment)
        layout.addWidget(self._kind_pohi)

        # Target file (read-only)
        layout.addWidget(QLabel('Target file:'))
        self._file_label = QLineEdit(self._filepath)
        self._file_label.setReadOnly(True)
        self._file_label.setStyleSheet('color: gray; font-size: 9px;')
        layout.addWidget(self._file_label)

        # The file's anchor info
        config = settings.load()
        file_anchor = config.get('file_anchors', {}).get(self._filepath)
        if file_anchor:
            count = file_anchor.get('anchor_count', 1)
            ts = file_anchor.get('timestamp', '')
            last = f"{ts[:10]} {ts[11:16]}" if len(ts) >= 16 else ts
            anchor_info = f"Anchored {count} time(s) — last: {last}"
            color = 'green'
        else:
            anchor_info = "This file has no anchors yet. Save it first."
            color = 'orange'
        anchor_label = QLabel(anchor_info)
        anchor_label.setStyleSheet(f'color: {color}; font-size: 9px;')
        layout.addWidget(anchor_label)

        # Actor ID (shown only for assessment requests)
        self._actor_label = QLabel("Actor's Terminal ID (the counterparty AI's UUID):")
        layout.addWidget(self._actor_label)
        self._actor_id = QLineEdit()
        self._actor_id.setPlaceholderText("Enter the counterparty AI's Terminal ID")
        layout.addWidget(self._actor_id)

        # Description
        self._desc_label = QLabel('Incident description:')
        layout.addWidget(self._desc_label)
        self._description = QTextEdit()
        self._description.setFixedHeight(100)
        layout.addWidget(self._description)

        # Note (swapped according to the request kind)
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
        # PoHI has no Actor: hide the Actor fields.
        self._actor_label.setVisible(not pohi)
        self._actor_id.setVisible(not pohi)
        if pohi:
            self._desc_label.setText('Work description:')
            self._description.setPlaceholderText('Describe what you created — the work you want to attest')
            self._note.setText('Note: human involvement is assessed from the continuity of this '
                               "work's anchor chain (the record of your process), and a "
                               'POH_CERTIFICATE is issued (RFC-0001 §8).')
        else:
            self._desc_label.setText('Incident description:')
            self._description.setPlaceholderText('Describe what happened and what you are claiming')
            self._note.setText('Note: the latest anchor of the current session log is submitted automatically as evidence.')

    def _on_accept(self):
        if not self._description.toPlainText().strip():
            self._description.setStyleSheet('border: 1px solid red;')
            return
        self.accept()

    def actor_id(self) -> str:
        # PoHI has no Actor (§8): return an empty string; the caller turns it into an omitted actor_id.
        if self._is_pohi():
            return ''
        return self._actor_id.text().strip()

    def description(self) -> str:
        return self._description.toPlainText().strip()

    def filepath(self) -> str:
        return self._filepath
