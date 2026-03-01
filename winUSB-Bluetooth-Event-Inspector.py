import sys, os, re, sqlite3, ctypes
import datetime
from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QLineEdit, QLabel, QTabWidget, QFileDialog, QMessageBox
)
from PySide6.QtGui import QIcon, QFont, QDesktopServices
from PySide6.QtCore import Qt, QUrl
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.pagesizes import landscape, A4
from reportlab.lib import colors
from Evtx.Evtx import Evtx
import winreg
import pandas as pd

# --------------------- Admin Permission Check ---------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )

# --------------------- Database Setup -----------------------------
DB_PATH = "forensic_data.db"
conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

c.execute("""
CREATE TABLE IF NOT EXISTS usb_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name TEXT,
    serial TEXT,
    first_connected TEXT,
    last_connected TEXT,
    times_connected INTEGER,
    source TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS bt_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name TEXT,
    mac_address TEXT,
    first_connected TEXT,
    last_connected TEXT,
    times_connected INTEGER,
    source TEXT
)
""")

c.execute("""
CREATE TABLE IF NOT EXISTS deleted_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_name TEXT,
    serial_or_mac TEXT,
    source TEXT
)
""")

conn.commit()
conn.close()

# --------------------- Windows Info -------------------------------
def get_windows_info():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        product = winreg.QueryValueEx(key, "ProductName")[0]
        release = winreg.QueryValueEx(key, "ReleaseId")[0]
        build = winreg.QueryValueEx(key, "CurrentBuild")[0]
        install_ts = winreg.QueryValueEx(key, "InstallDate")[0]
        install_date = datetime.datetime.fromtimestamp(int(install_ts)).strftime("%Y-%m-%d %H:%M:%S")
        return {"Product": product, "Release": release, "Build": build, "InstallDate": install_date}
    except:
        return {}

# --------------------- USB Scan -----------------------------
def scan_usb():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # EVTX logs
    evtx_dir = r"C:\Windows\System32\winevt\Logs"
    for filename in os.listdir(evtx_dir):
        if filename.endswith(".evtx"):
            filepath = os.path.join(evtx_dir, filename)
            try:
                with Evtx(filepath) as log:
                    for record in log.records():
                        xml = record.xml()
                        if "USB" in xml or "usbstor" in xml.lower():
                            ts_match = re.search(r"SystemTime=\"(.*?)\"", xml)
                            data_match = re.search(r"<Data>(.*?)</Data>", xml)
                            if ts_match and data_match:
                                ts = ts_match.group(1)
                                device = data_match.group(1)
                                c.execute("SELECT id FROM deleted_records WHERE serial_or_mac=? AND source='USB'", (device,))
                                if c.fetchone(): continue
                                c.execute("SELECT id, first_connected FROM usb_events WHERE serial=?", (device,))
                                row = c.fetchone()
                                if row:
                                    c.execute("UPDATE usb_events SET last_connected=?, times_connected=times_connected+1 WHERE id=?", (ts,row[0]))
                                else:
                                    c.execute("INSERT INTO usb_events (device_name, serial, first_connected, last_connected, times_connected, source) VALUES (?,?,?,?,?,?)",
                                              (device, device, ts, ts, 1, "EVTX"))
            except: pass

    # Registry USBSTOR
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
        for i in range(winreg.QueryInfoKey(key)[0]):
            device = winreg.EnumKey(key,i)
            subkey = winreg.OpenKey(key,device)
            for j in range(winreg.QueryInfoKey(subkey)[0]):
                serial = winreg.EnumKey(subkey,j)
                c.execute("SELECT id FROM deleted_records WHERE serial_or_mac=? AND source='USB'", (serial,))
                if c.fetchone(): continue
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                c.execute("SELECT id FROM usb_events WHERE serial=?", (serial,))
                if not c.fetchone():
                    c.execute("INSERT INTO usb_events (device_name, serial, first_connected, last_connected, times_connected, source) VALUES (?,?,?,?,?,?)",
                              (device, serial, now, now, 1, "Registry"))
    except: pass

    # SetupAPI logs
    setup_log = r"C:\Windows\inf\setupapi.dev.log"
    if os.path.exists(setup_log):
        with open(setup_log,"r",errors="ignore") as f:
            content = f.read()
            found = re.findall(r"USBSTOR\\.*", content)
            for dev in found:
                c.execute("SELECT id FROM deleted_records WHERE serial_or_mac=? AND source='USB'", (dev,))
                if c.fetchone(): continue
                c.execute("SELECT id FROM usb_events WHERE serial=?", (dev,))
                if not c.fetchone():
                    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    c.execute("INSERT INTO usb_events (device_name, serial, first_connected, last_connected, times_connected, source) VALUES (?,?,?,?,?,?)",
                              (dev, dev, now, now, 1, "SetupAPI"))
    conn.commit()
    conn.close()

# --------------------- Bluetooth Scan -----------------------------
def scan_bt():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Registry Bluetooth
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices")
        for i in range(winreg.QueryInfoKey(key)[0]):
            mac = winreg.EnumKey(key,i)
            subkey = winreg.OpenKey(key,mac)
            try:
                name = winreg.QueryValueEx(subkey,"Name")[0]
            except: name = mac
            c.execute("SELECT id FROM deleted_records WHERE serial_or_mac=? AND source='BT'",(mac,))
            if c.fetchone(): continue
            now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            c.execute("SELECT id FROM bt_events WHERE mac_address=?", (mac,))
            if not c.fetchone():
                c.execute("INSERT INTO bt_events (device_name, mac_address, first_connected, last_connected, times_connected, source) VALUES (?,?,?,?,?,?)",
                          (name,mac,now,now,1,"Registry"))
    except: pass

    # EVTX Bluetooth
    evtx_dir = r"C:\Windows\System32\winevt\Logs"
    for filename in os.listdir(evtx_dir):
        if filename.endswith(".evtx"):
            filepath = os.path.join(evtx_dir,filename)
            try:
                with Evtx(filepath) as log:
                    for record in log.records():
                        xml = record.xml()
                        if "Bluetooth" in xml:
                            ts_match = re.search(r"SystemTime=\"(.*?)\"", xml)
                            data_match = re.search(r"<Data>(.*?)</Data>", xml)
                            if ts_match and data_match:
                                ts = ts_match.group(1)
                                device = data_match.group(1)
                                c.execute("SELECT id FROM deleted_records WHERE serial_or_mac=? AND source='BT'", (device,))
                                if c.fetchone(): continue
                                c.execute("SELECT id FROM bt_events WHERE mac_address=?", (device,))
                                if not c.fetchone():
                                    c.execute("INSERT INTO bt_events (device_name, mac_address, first_connected, last_connected, times_connected, source) VALUES (?,?,?,?,?,?)",
                                              (device, device, ts, ts, 1, "EVTX"))
            except: pass
    conn.commit()
    conn.close()

# --------------------- GUI -----------------------------
class MergedApp(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Win USB & Bluetooth Event Inspector")
        app.setWindowIcon(QIcon("assets/icon.ico"))
        self.setGeometry(100,100,1200,650)
        self.setStyleSheet("background-color:#1E1E1E; color:white; font-size:12px;")
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # Windows Info
        self.win_lbl = QLabel()
        font = QFont()
        font.setPointSize(11)
        font.setBold(True)
        self.win_lbl.setFont(font)
        self.layout.addWidget(self.win_lbl)
        self.load_windows_info()

        # Tabs
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)
        self.usb_tab = QWidget()
        self.bt_tab = QWidget()
        self.tabs.addTab(self.usb_tab,"USB Devices")
        self.tabs.addTab(self.bt_tab,"Bluetooth Devices")
        self.setup_usb_tab()
        self.setup_bt_tab()

        # Footer Buttons
        footer = QHBoxLayout()
        self.github_btn = QPushButton("GitHub")
        self.github_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/Sajawal-hacker")))
        self.linkedin_btn = QPushButton("LinkedIn")
        self.linkedin_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://www.linkedin.com/in/sajawalhacker")))
        footer.addWidget(self.github_btn)
        footer.addWidget(self.linkedin_btn)
        self.layout.addLayout(footer)

    def load_windows_info(self):
        info = get_windows_info()
        if info:
            self.win_lbl.setText(f"Windows: {info['Product']} | Build: {info['Build']} | Release: {info['Release']} | Installed: {info['InstallDate']}")
        else:
            self.win_lbl.setText("Windows Info: Not Available")

    # ---------------- USB Tab ----------------
    def setup_usb_tab(self):
        layout = QVBoxLayout()
        scan_btn = QPushButton("Scan USB")
        scan_btn.setStyleSheet("background-color:#007ACC; color:white; padding:8px;")
        scan_btn.clicked.connect(self.scan_usb_tab)
        layout.addWidget(scan_btn)

        self.usb_table = QTableWidget()
        layout.addWidget(self.usb_table)

        # Save Buttons
        save_layout = QHBoxLayout()
        save_excel = QPushButton("Save USB Excel")
        save_excel.setStyleSheet("background-color:#16A085; color:white;")
        save_excel.clicked.connect(self.save_usb_excel)
        save_pdf = QPushButton("Save USB PDF")
        save_pdf.setStyleSheet("background-color:#E67E22; color:white;")
        save_pdf.clicked.connect(self.save_usb_pdf)
        save_layout.addWidget(save_excel)
        save_layout.addWidget(save_pdf)
        layout.addLayout(save_layout)

        self.usb_tab.setLayout(layout)

    # ---------------- Bluetooth Tab ----------------
    def setup_bt_tab(self):
        layout = QVBoxLayout()
        scan_btn = QPushButton("Scan Bluetooth")
        scan_btn.setStyleSheet("background-color:#007ACC; color:white; padding:8px;")
        scan_btn.clicked.connect(self.scan_bt_tab)
        layout.addWidget(scan_btn)

        self.bt_table = QTableWidget()
        layout.addWidget(self.bt_table)

        # Save Buttons
        save_layout = QHBoxLayout()
        save_excel = QPushButton("Save BT Excel")
        save_excel.setStyleSheet("background-color:#16A085; color:white;")
        save_excel.clicked.connect(self.save_bt_excel)
        save_pdf = QPushButton("Save BT PDF")
        save_pdf.setStyleSheet("background-color:#E67E22; color:white;")
        save_pdf.clicked.connect(self.save_bt_pdf)
        save_layout.addWidget(save_excel)
        save_layout.addWidget(save_pdf)
        layout.addLayout(save_layout)

        self.bt_tab.setLayout(layout)

    # ---------------- Scan Functions ----------------
    def scan_usb_tab(self):
        scan_usb()
        QMessageBox.information(self,"Done","USB Scan Complete!")
        self.load_usb_table()

    def scan_bt_tab(self):
        scan_bt()
        QMessageBox.information(self,"Done","Bluetooth Scan Complete!")
        self.load_bt_table()

    # ---------------- Load Tables ----------------
    def load_usb_table(self):
        conn = sqlite3.connect(DB_PATH)
        rows = conn.cursor().execute("SELECT device_name, serial, first_connected, last_connected, times_connected, source FROM usb_events").fetchall()
        conn.close()
        self.usb_table.setRowCount(len(rows))
        self.usb_table.setColumnCount(6)
        self.usb_table.setHorizontalHeaderLabels(["Device Name","Serial","First","Last","Times","Source"])
        for i,row in enumerate(rows):
            for j,val in enumerate(row):
                self.usb_table.setItem(i,j,QTableWidgetItem(str(val)))

    def load_bt_table(self):
        conn = sqlite3.connect(DB_PATH)
        rows = conn.cursor().execute("SELECT device_name, mac_address, first_connected, last_connected, times_connected, source FROM bt_events").fetchall()
        conn.close()
        self.bt_table.setRowCount(len(rows))
        self.bt_table.setColumnCount(6)
        self.bt_table.setHorizontalHeaderLabels(["Device Name","MAC","First","Last","Times","Source"])
        for i,row in enumerate(rows):
            for j,val in enumerate(row):
                self.bt_table.setItem(i,j,QTableWidgetItem(str(val)))

    # ---------------- Save Functions ----------------
    def save_usb_excel(self):
        df = pd.read_sql_query("SELECT * FROM usb_events", sqlite3.connect(DB_PATH))
        path,_ = QFileDialog.getSaveFileName(self,"Save USB Excel","USB_Report.xlsx","Excel Files (*.xlsx)")
        if path: df.to_excel(path,index=False); QMessageBox.information(self,"Saved","USB Excel saved!")

    def save_bt_excel(self):
        df = pd.read_sql_query("SELECT * FROM bt_events", sqlite3.connect(DB_PATH))
        path,_ = QFileDialog.getSaveFileName(self,"Save BT Excel","BT_Report.xlsx","Excel Files (*.xlsx)")
        if path: df.to_excel(path,index=False); QMessageBox.information(self,"Saved","Bluetooth Excel saved!")

    def save_usb_pdf(self):
        path,_ = QFileDialog.getSaveFileName(self,"Save USB PDF","USB_Report.pdf","PDF Files (*.pdf)")
        if path:
            conn = sqlite3.connect(DB_PATH)
            data = conn.cursor().execute("SELECT device_name, serial, first_connected, last_connected, times_connected, source FROM usb_events").fetchall()
            conn.close()
            data_pdf = [("Device Name","Serial","First Connected","Last Connected","Times Connected","Source")] + list(data)
            doc = SimpleDocTemplate(path,pagesize=landscape(A4))
            table = Table(data_pdf)
            table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.gray),('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),('GRID',(0,0),(-1,-1),1,colors.black),('ALIGN',(0,0),(-1,-1),'CENTER')]))
            doc.build([table])
            QMessageBox.information(self,"Saved","USB PDF saved!")

    def save_bt_pdf(self):
        path,_ = QFileDialog.getSaveFileName(self,"Save BT PDF","BT_Report.pdf","PDF Files (*.pdf)")
        if path:
            conn = sqlite3.connect(DB_PATH)
            data = conn.cursor().execute("SELECT device_name, mac_address, first_connected, last_connected, times_connected, source FROM bt_events").fetchall()
            conn.close()
            data_pdf = [("Device Name","MAC","First Connected","Last Connected","Times Connected","Source")] + list(data)
            doc = SimpleDocTemplate(path,pagesize=landscape(A4))
            table = Table(data_pdf)
            table.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.gray),('TEXTCOLOR',(0,0),(-1,0),colors.whitesmoke),('GRID',(0,0),(-1,-1),1,colors.black),('ALIGN',(0,0),(-1,-1),'CENTER')]))
            doc.build([table])
            QMessageBox.information(self,"Saved","Bluetooth PDF saved!")

# --------------------- Run App ---------------------
if __name__ == "__main__":
    run_as_admin()
    app = QApplication(sys.argv)
    window = MergedApp()
    window.show()
    sys.exit(app.exec())