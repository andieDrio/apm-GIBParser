"""Group-IB Threat Intelligence Suite - PyQt6 application shell."""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QFileDialog,
)

from config import AppConfig
from pdf_generator import PDFReportGenerator, ThreatReport


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Group-IB Threat Intelligence Suite")
        self.resize(1280, 800)

        self._accounts: list[list[str]] = []
        self._stealers: list[list[str]] = []
        self._metrics = {
            "Total Breaches": 0,
            "Infostealer Infections": 0,
            "Active Session Cookies": 0,
        }

        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.setPlaceholderText("Group-IB TI&A API Key")

        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Target domain filter (optional)")

        fetch_button = QPushButton("Fetch & Analyze")
        fetch_button.clicked.connect(self._fetch_and_analyze)

        header = QHBoxLayout()
        header.addWidget(self.api_key_input, 2)
        header.addWidget(self.domain_input, 1)
        header.addWidget(fetch_button)

        cards = QGridLayout()
        self.metric_labels: dict[str, QLabel] = {}
        for column, name in enumerate(self._metrics):
            frame = QFrame()
            frame.setObjectName("metricCard")
            layout = QVBoxLayout(frame)
            title = QLabel(name)
            value = QLabel("0")
            value.setObjectName("metricValue")
            layout.addWidget(title)
            layout.addWidget(value)
            cards.addWidget(frame, 0, column)
            self.metric_labels[name] = value

        self.accounts_table = QTableWidget()
        self.accounts_table.setColumnCount(0)
        self.stealers_table = QTableWidget()
        self.stealers_table.setColumnCount(0)
        self.raw_output = QTextEdit()
        self.raw_output.setReadOnly(True)

        tabs = QTabWidget()
        tabs.addTab(self.accounts_table, "Compromised Credentials")
        tabs.addTab(self.stealers_table, "Infostealers & Cookies")
        tabs.addTab(self.raw_output, "Raw JSON / Logs")

        export_button = QPushButton("Export PDF Report")
        export_button.clicked.connect(self._export_pdf)

        root = QVBoxLayout()
        root.addLayout(header)
        root.addLayout(cards)
        root.addWidget(tabs)
        root.addWidget(export_button)

        container = QWidget()
        container.setLayout(root)
        self.setCentralWidget(container)
        self._apply_dark_theme()

    def _fetch_and_analyze(self) -> None:
        if not self.api_key_input.text().strip():
            QMessageBox.warning(self, "API Key Required", "Enter a Group-IB API key.")
            return
        self.raw_output.append("Fetch & Analyze event received. API integration gate is next.")

    def _export_pdf(self) -> None:
        default_path = str(Path("exports") / "group_ib_threat_report.pdf")
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export PDF Threat Report",
            default_path,
            "PDF Files (*.pdf)",
        )
        if not path:
            return

        report = ThreatReport(
            metrics=self._metrics,
            accounts=self._accounts,
            stealers=self._stealers,
        )
        PDFReportGenerator().generate(report, path)
        QMessageBox.information(self, "PDF Export", f"Report exported to:\n{path}")

    def _apply_dark_theme(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QWidget { background: #17191c; color: #e7e9ec; }
            QLineEdit, QTextEdit, QTableWidget {
                background: #202329; color: #e7e9ec;
                border: 1px solid #3a3f46; border-radius: 6px;
                padding: 6px;
            }
            QPushButton {
                background: #2d333b; color: #ffffff;
                border: 1px solid #4a515b; border-radius: 6px;
                padding: 8px 14px;
            }
            QPushButton:hover { background: #3a424c; }
            QFrame#metricCard {
                background: #202329; border: 1px solid #3a3f46;
                border-radius: 8px;
            }
            QLabel#metricValue { font-size: 24px; font-weight: 700; }
            QTabWidget::pane { border: 1px solid #3a3f46; }
            QHeaderView::section {
                background: #2a2f36; color: #e7e9ec; padding: 6px;
            }
            """
        )


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Group-IB Threat Intelligence Suite")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
