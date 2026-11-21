# VA Scanner

GUI สำหรับทีม VA ครอบ [nuclei](../README.md) และมีการตรวจ SSL/TLS แบบ testssl.sh (ใช้ [sslyze](https://github.com/nabla-c0d3/sslyze))

- **My Scans / New Scan / Results**: จัดการงานสแกน, เลือกรูปแบบการสแกนจากการ์ด, ผลแยกตามช่องโหว่และเครื่อง, อัปเดตสดระหว่างสแกน
- **SSL/TLS**: ตรวจโปรโตคอล, cipher, ใบรับรอง, Heartbleed/ROBOT/CCS/CRIME ฯลฯ พร้อมเกรด A+–F/T (วิธีคิดแบบ SSL Labs) และรายการ cipher ครบ
- **รายงาน HTML** ต่อสแกน (`reports/<วันเวลา>/report.html`)
- ทุกสแกนต้องยืนยันว่าได้รับอนุญาต และสแกนแบบ intrusive ต้องให้หัวหน้าอนุมัติ

## Build

ต้องมี Python 3 บน Windows

```bat
pip install pyinstaller sslyze
build.bat
```

จะได้ `dist\VA-Scanner\` จากนั้นวาง [`nuclei.exe`](https://github.com/projectdiscovery/nuclei/releases) ไว้ข้าง `VA-Scanner.exe` ส่วน templates โปรแกรมจะดาวน์โหลดเองตอนเปิดครั้งแรก
ตอนแชร์ให้ทีม ให้ zip โฟลเดอร์นั้นโดย **ไม่รวม `reports\`** (ในนั้นมีผลสแกนของลูกค้า)

## รันจากซอร์ส

```bat
python nuclei_gui.py          :: GUI (nuclei.exe ต้องอยู่โฟลเดอร์เดียวกัน)
python nuclei_gui.py --test   :: self-check
python nuclei_gui.py --tls https://host out.json   :: ตรวจ TLS อย่างเดียว
```
