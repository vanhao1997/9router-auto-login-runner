Infinity AI Store - Import 9router Tool v2.1
==============================================

Yeu cau truoc khi chay:
- Windows 10/11 64-bit.
- May phai co cai san Python 3.11 tro len (64-bit).
- Luc cai PHáº¢I tick: Add python.exe to PATH.
- Da cai va dang nhap 9router tren may.

Tinh nang:
- Auto Login OAuth Codex hang loat, chay song song nhieu tai khoan.
- Tu nhap so luong ngay tren giao dien (mac dinh 3, khong gioi han cung).
- Callback OAuth dung localhost:1455 va tu phan luong theo state, tranh lan ket qua giua cac nick.
- Ho tro email|password|2FA.
- Tu dong convert dinh dang paste tu file/tab/comma/space.
- Moi tai khoan chay browser rieng, sach session.
- Realtime logs, tien do va danh sach nick dang chay tren giao dien.
- Import refresh token vao 9router va kiem chung SQLite sau khi ghi.

Cach chay (tu setup tu dong):
1. Giai nen file ZIP vao mot thu muc rieng.
2. Double-click: khoi_dong_o_day.bat.
3. Lan dau file bat tu dong:
   - Kiem tra Python va pip.
   - Cai/cap nhat pyotp + playwright.
   - Tai Chromium cho Playwright.
   - Khoi dong server tool.
4. Trinh duyet se tu mo tai: http://localhost:9876
5. Vao tab Auto Login, dan danh sach nick va nhap so luong muon chay.

Neu bao khong tim thay Python:\r`n- Cai Python 3.11 64-bit tro len, sau do dong va mo lai khoi_dong_o_day.bat.

Luu y:
- Can internet khi cai lan dau va trong luc dang nhap OAuth.
- Nhieu luong hon se ton RAM/CPU va co the gap captcha/xac minh nhieu hon.
- Khong nen xoa auto_login.py, server.py hoac index.html trong thu muc da giai nen.
- Khong can cai thu cong neu khoi_dong_o_day.bat chay thanh cong.

V1 deploy tren Coolify (runner rieng):
1. Tao mot Coolify application moi tu Dockerfile nay, expose port 9876.
2. Bat HTTPS va HTTP Basic Auth cho runner. Khong public runner API khong bao ve.
3. Tao API key trong 9router dashboard, sau do dat cac env sau trong runner:
   - N9ROUTER_IMPORT_API=https://9router.vibecodingsolution.ovh/api/v1/oauth/codex/bulk-import
   - N9ROUTER_IMPORT_API_KEY=<API key cua 9router>
   - N9ROUTER_IMPORT_FORMAT=codex-bulk
   - N9ROUTER_IMPORT_AUTH_MODE=api-key
   - TOOL_ALLOWED_ORIGIN=https://login.9router.vibecodingsolution.ovh
   - AUTO_LOGIN_DEBUG=false
4. Deploy 9router branch co route API-key-protected alias. Runner giu callback OAuth
   localhost:1455 ben trong container, khong can public port 1455.
5. Mo runner qua domain rieng (vi du login.9router.vibecodingsolution.ovh) va nhap
   tai khoan trong HTTPS page. Token chi gui toi 9router API, khong hien trong response.

Khong thay doi 9router: dung endpoint bulk-import hien co va dat runner env:
   - N9ROUTER_IMPORT_API=https://9router.vibecodingsolution.ovh/api/oauth/codex/bulk-import
   - N9ROUTER_IMPORT_FORMAT=codex-bulk
   - N9ROUTER_IMPORT_AUTH_MODE=dashboard-password
   - N9ROUTER_DASHBOARD_PASSWORD=<dashboard password, chi dat trong Coolify secret>
Dashboard password chi dung de lay HTTP-only session trong bo nho runner. API-key mode
van an toan hon va nen dung sau khi endpoint /api/v1/... duoc deploy.

Workstation manual OAuth (khuyen nghi khi VPS gap Cloudflare/anti-bot):
1. Clone repo tren may co Chrome that, khong chay trong container VPS.
2. Cai dependency: `python -m pip install -r requirements.txt`.
3. Dat env remote import trong phien terminal hien tai, dung API key uu tien:
   - `N9ROUTER_IMPORT_API=https://9router.vibecodingsolution.ovh/api/oauth/codex/bulk-import`
   - `N9ROUTER_IMPORT_FORMAT=codex-bulk`
   - `N9ROUTER_IMPORT_AUTH_MODE=api-key`
   - `N9ROUTER_IMPORT_API_KEY=<API key cua 9router>`
   - `TOOL_BIND_HOST=127.0.0.1`
   - `TOOL_OPEN_BROWSER=true`
   - `TOOL_HEADLESS_DEFAULT=false`
4. Chay `python server.py`, mo `http://localhost:9876`, chon `Manual Login`.
5. Dang nhap tung account trong Chrome workstation. Callback `localhost:1455` doi token
   tai workstation, sau do chi gui connection da nhan token toi `N9ROUTER_IMPORT_API`.

Khong dat password, API key, refresh token vao repo, README, screenshot, hoac chat. Manual
OAuth tren domain runner VPS khong tu dong mo Chrome tren may workstation va khong dung
duoc callback localhost; hay chay server.py local theo huong dan tren.

