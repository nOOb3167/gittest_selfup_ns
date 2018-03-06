#include <cassert>
#include <cstring>

#include <thread>
#include <chrono>
#include <memory>
#include <string>
#include <random>

#include <windows.h>
#include <wingdi.h>

#include <selfup/ns_gui.h>
#include <selfup/ns_log.h>
#include <imgpbblip_96_32_.h>
#include <imgpbempty_384_32_.h>
#include <imgpbfull_384_32_.h>
#include <imglogo_100_100_.h>

#define GS_GUI_WIN_MAGIC_MSGNUM_QUIT (WM_USER + 0x5423)
#define GS_GUI_WIN_MAGIC_MSGNUM_REFRESH (WM_USER + 0x5424)

#define GS_GUI_WIN_FRAMERATE 30

#define GS_GUI_WIN_READIMAGE_B(hdc, lump) win_readimage_b(hdc, std::string(# lump), std::string((char *)(lump), sizeof (lump)))

#define NS_GUI_LOG_ERR(cstr) do { NS_LOG_SZ(cstr, strlen(cstr)); } while (0)

namespace ns_gui
{

struct DeleteHdcData
{
	DeleteHdcData(HWND hwnd, HDC hdc) :
		hwnd(hwnd),
		hdc(hdc)
	{
		if (! hdc)
			throw std::runtime_error("win hdc");
	}

	HWND hwnd;
	HDC hdc;
};

typedef ::std::unique_ptr<HBITMAP, void(*)(HBITMAP *)> unique_ptr_hbitmap;
typedef ::std::unique_ptr<DeleteHdcData, void(*)(DeleteHdcData *)> unique_ptr_hdc;
typedef ::std::unique_ptr<WNDCLASSEX, void(*)(WNDCLASSEX *)> unique_ptr_wndclassex;

void deleteHBitmap(HBITMAP *p)
{
	if (p)
		DeleteObject(*p);
}

void deleteHdc(DeleteHdcData *p)
{
	if (p) {
		ReleaseDC(p->hwnd, p->hdc);
		delete p;
	}
}

void deleteWndclassex(WNDCLASSEX *p)
{
	if (p) {
		UnregisterClass(p->lpszClassName, p->hInstance);
		delete p;
	}
}

class AuxImgB
{
public:
	AuxImgB() :
		m_name(),
		m_width(0),
		m_height(0),
		m_hbitmap(NULL, deleteHBitmap)
	{}

	std::string m_name;
	int m_width;
	int m_height;
	unique_ptr_hbitmap m_hbitmap;
};

AuxImgB g_img_pb_empty;
AuxImgB g_img_pb_full;
AuxImgB g_img_pb_blip;
AuxImgB g_img_logo;

const char GsGuiWinClassName[] = "GsGuiWinClass";
const char GsGuiWinWindowName[] = "Selfupdate";

unique_ptr_hbitmap win_bitmap_from_rgb(
	HDC hdc,
	int width, int height,
	const std::string &img_data_buf)
{
	/* https://msdn.microsoft.com/en-us/library/ms969901.aspx
	     GetDIBits section example
		 if everything else fails - just call StretchDIBits from WM_PAINT
	*/

	if (img_data_buf.size() != width * height * 3)
		throw std::runtime_error("win bitmap size");

	std::string tmpbuf(width * height * 4, '\0');

	for (int y = 0; y < height; y++)
		for (int x = 0; x < width; x++) {
			tmpbuf[width * 4 * (height-1-y) + 4 * x + 0] = img_data_buf[width * 3 * y + 3 * x + 2];
			tmpbuf[width * 4 * (height-1-y) + 4 * x + 1] = img_data_buf[width * 3 * y + 3 * x + 1];
			tmpbuf[width * 4 * (height-1-y) + 4 * x + 2] = img_data_buf[width * 3 * y + 3 * x + 0];
			tmpbuf[width * 4 * (height-1-y) + 4 * x + 3] = 0;
		}

	// FIXME: using hdc instead of hdc2 fixes most fields of GetObject
	unique_ptr_hbitmap hbitmap(new HBITMAP(CreateCompatibleBitmap(hdc, width, height)), deleteHBitmap);
	if (! hbitmap)
		throw std::runtime_error("win bitmap create");;

	BITMAPINFO bitmapinfo = {};
	bitmapinfo.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	bitmapinfo.bmiHeader.biWidth = width;
	bitmapinfo.bmiHeader.biHeight = height;
	bitmapinfo.bmiHeader.biPlanes = 1;
	bitmapinfo.bmiHeader.biBitCount = 32;
	bitmapinfo.bmiHeader.biCompression = BI_RGB;
	bitmapinfo.bmiHeader.biSizeImage = 0;
	bitmapinfo.bmiHeader.biXPelsPerMeter = 0;
	bitmapinfo.bmiHeader.biYPelsPerMeter = 0;
	bitmapinfo.bmiHeader.biClrUsed = 0;
	bitmapinfo.bmiHeader.biClrImportant = 0;

	/* referenced example has hdc for SetDIBits and hdc2 for CreateCompatibleBitmap
	   but describes CreateDIBitmap in terms of using the CreateCompatibleBitmap DC for both calls */
	// FIXME: "The scan lines must be aligned on a DWORD except for RLE-compressed bitmaps."
	//   https://msdn.microsoft.com/en-us/library/windows/desktop/dd162973(v=vs.85).aspx
	assert((unsigned long long) tmpbuf.data() % 4 == 0);
	if (! SetDIBits(hdc, *hbitmap, 0, height, tmpbuf.data(), &bitmapinfo, DIB_RGB_COLORS))
		throw std::runtime_error("win bitmap setdibits");;

	return hbitmap;
}

AuxImgB win_readimage_b(
	HDC hdc,
	const std::string &filename,
	const std::string &data)
{
	AuxImg img = readimage_data(filename, data);

	unique_ptr_hbitmap hbitmap = win_bitmap_from_rgb(
		hdc,
		img.m_width, img.m_height,
		img.m_data);

	AuxImgB imgb;
	imgb.m_name = img.m_name;
	imgb.m_width = img.m_width;
	imgb.m_height = img.m_height;
	imgb.m_hbitmap = std::move(hbitmap);

	return imgb;
}

void win_drawimage_mask_b(
	HDC hdc,
	UINT color_transparent_rgb,
	AuxImgB *img_draw,
	int src_x, int src_y,
	int width, int height,
	int dst_x, int dst_y)
{
	HDC hdc2 = NULL;
	HGDIOBJ hobject_old = NULL;
	try {
		if (!(hdc2 = CreateCompatibleDC(hdc)))
			throw std::runtime_error("win create compatible dc");

		hobject_old = SelectObject(hdc2, *img_draw->m_hbitmap);

		/* TransparentBlt fails on zero dimensions */
		if (width != 0 && height != 0)
			if (! TransparentBlt(hdc, dst_x, dst_y, width, height, hdc2, src_x, src_y, width, height, color_transparent_rgb))
				throw std::runtime_error("win blt transparent");
	}
	catch (const std::exception &e) {
		if (hobject_old && hdc2)
			SelectObject(hdc2, hobject_old);
		if (hdc2)
			DeleteDC(hdc2);
		throw;
	}

	if (hobject_old && hdc2)
		SelectObject(hdc2, hobject_old);
	if (hdc2)
		DeleteDC(hdc2);
}

void win_clear_window(
	HWND hwnd,
	HDC hdc)
{
	HBRUSH bgbrush = NULL;
	try {

		RECT window_rect = {};
		if (! GetWindowRect(hwnd, &window_rect))
			throw std::runtime_error("win get window rect");

		RECT clear_rect = {};
		clear_rect.left = 0;
		clear_rect.top = 0;
		clear_rect.right = window_rect.right - window_rect.left;
		clear_rect.bottom = window_rect.bottom - window_rect.top;

		if (! (bgbrush = CreateSolidBrush(RGB(0xFF, 0xFF, 0xFF))))
			throw std::runtime_error("win create solid brush");

		if (! FillRect(hdc, &clear_rect, bgbrush))
			throw std::runtime_error("win fill rect");
	}
	catch (const std::exception &e) {
		if (bgbrush)
			DeleteObject(bgbrush);
	}

	if (bgbrush)
		DeleteObject(bgbrush);
}

void win_draw_progress_ratio(
	HDC hdc,
	AuxImgB *img_pb_empty,
	AuxImgB *img_pb_full,
	int dst_x, int dst_y,
	int ratio_a, int ratio_b)
{
	float ratio = 0.0f;
	if (ratio_b)
		ratio = (float)ratio_a / ratio_b;

	win_drawimage_mask_b(hdc, GS_GUI_COLOR_MASK_RGB, img_pb_empty, 0, 0, img_pb_empty->m_width, img_pb_empty->m_height, dst_x, dst_y);
	win_drawimage_mask_b(hdc, GS_GUI_COLOR_MASK_RGB, img_pb_full, 0, 0, img_pb_full->m_width * ratio, img_pb_full->m_height, dst_x, dst_y);
}

void win_draw_progress_blip(
  HDC hdc,
  AuxImgB *img_pb_empty,
  AuxImgB *img_pb_blip,
  int dst_x, int dst_y,
  int blipcnt)
{
  int src_x = 0, draw_left = 0, draw_width = 0;

  progress_blip_calc(blipcnt, img_pb_empty->m_width, img_pb_blip->m_width, &src_x, &draw_left, &draw_width);

  win_drawimage_mask_b(hdc, GS_GUI_COLOR_MASK_RGB, img_pb_blip, src_x, 0, draw_width, img_pb_blip->m_height, dst_x + draw_left, dst_y);
  win_drawimage_mask_b(hdc, GS_GUI_COLOR_MASK_RGB, img_pb_empty, 0, 0, img_pb_empty->m_width, img_pb_empty->m_height, dst_x, dst_y);
}

void win_draw_progress_status(
	HDC hdc,
	int dst_x, int dst_y,
	const std::string &msg)
{
	if (! TextOut(hdc, dst_x, dst_y, msg.c_str(), msg.size()))
		throw std::runtime_error("win text out");
}

void win_draw_redraw_window(HWND hwnd, HDC hdc)
{
	win_clear_window(hwnd, hdc);

	std::unique_lock<std::mutex> lock(g_gui_ctx->getMutex());

	win_drawimage_mask_b(hdc, GS_GUI_COLOR_MASK_RGB, &g_img_logo, 0, 0, g_img_logo.m_width, g_img_logo.m_height, 164, 60);

	switch (g_gui_ctx->getProgress().m_mode)
	{
	case 0:
	{
		win_draw_progress_ratio(
			hdc,
			&g_img_pb_empty,
			&g_img_pb_full,
			0, 32,
			g_gui_ctx->getProgress().m_ratio_a, g_gui_ctx->getProgress().m_ratio_b);
	}
	break;

	case 1:
	{
		win_draw_progress_blip(
			hdc,
			&g_img_pb_empty,
			&g_img_pb_blip,
			0, 32,
			g_gui_ctx->getProgress().m_blip_cnt);
	}
	break;

	default:
		assert(0);
	}

	win_draw_progress_status(hdc, 4, 64, g_gui_ctx->getProgress().m_status);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
	/* beware of throwing exceptions through foreign stack (eg out of WndProc) */

	switch (msg)
	{
	case WM_CREATE:
	{
		try {
			unique_ptr_hdc hdc_startup(new DeleteHdcData(hwnd, GetDC(hwnd)), deleteHdc);
			g_img_pb_empty = GS_GUI_WIN_READIMAGE_B(hdc_startup->hdc, imgpbempty_384_32_);
			g_img_pb_full = GS_GUI_WIN_READIMAGE_B(hdc_startup->hdc, imgpbfull_384_32_);
			g_img_pb_blip = GS_GUI_WIN_READIMAGE_B(hdc_startup->hdc, imgpbblip_96_32_);
			g_img_logo = GS_GUI_WIN_READIMAGE_B(hdc_startup->hdc, imglogo_100_100_);
		} catch (const std::exception &e) {
			NS_GUI_LOG_ERR("WM_CREATE");
		}
	}
	break;

	case WM_PAINT:
	{
		/* https://stackoverflow.com/a/21354578 */
		/* BeingPaint HDC 'released' by EndPaint */
		PAINTSTRUCT ps = {};	
		HDC hdc = BeginPaint(hwnd, &ps);
		assert(hdc);
		try {
			win_draw_redraw_window(hwnd, hdc);
		} catch (const std::exception &e) {
			NS_GUI_LOG_ERR("WM_PAINT");
		}
		EndPaint(hwnd, &ps);
	}
	break;

	case WM_DESTROY:
	{
		/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms632598(v=vs.85).aspx#destroying_win */
		PostQuitMessage(0);
	}
	break;

	default:
		return DefWindowProc(hwnd, msg, wparam, lparam);
	}
	return 0;
}

void win_threadfunc()
{
	const int frame_duration_ms = 1000 / GS_GUI_WIN_FRAMERATE;

	HINSTANCE hinstance = NULL;

	HWND hwnd = 0;
	BOOL ret = 0;
	MSG msg = {};

	/* NOTE: beware GetModuleHandle(NULL) caveat when called from DLL (should not apply here though) */
	if (! (hinstance = GetModuleHandle(NULL)))
		throw std::runtime_error("win get module handle");

	unique_ptr_wndclassex wc(new WNDCLASSEX(), deleteWndclassex);
	wc->cbSize = sizeof(WNDCLASSEX);
	wc->style = 0;
	wc->lpfnWndProc = WndProc;
	wc->cbClsExtra = 0;
	wc->cbWndExtra = 0;
	wc->hInstance = hinstance;
	wc->hIcon = LoadIcon(NULL, IDI_APPLICATION);
	wc->hCursor = LoadCursor(NULL, IDC_ARROW);
	wc->hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wc->lpszMenuName = NULL;
	wc->lpszClassName = GsGuiWinClassName;
	wc->hIconSm = LoadIcon(NULL, IDI_APPLICATION);

	if (! RegisterClassEx(wc.get()))
		throw std::runtime_error("win register class ex");

	if (! (hwnd = CreateWindowEx(
		WS_EX_CLIENTEDGE,
		GsGuiWinClassName,
		GsGuiWinWindowName,
		WS_OVERLAPPEDWINDOW,
		CW_USEDEFAULT, CW_USEDEFAULT, 400, 200,
		NULL, NULL, hinstance, NULL)))
	{
		throw std::runtime_error("win create window ex");
	}

	ShowWindow(hwnd, SW_SHOW);

	if (! UpdateWindow(hwnd))
		throw std::runtime_error("win update window");

	while ((ret = GetMessage(&msg, NULL, 0, 0)) != 0)
	{
		if (ret == -1)
			throw std::runtime_error("win getmessage");

		if (msg.message == WM_QUIT)
			break;
		if (msg.message == GS_GUI_WIN_MAGIC_MSGNUM_QUIT)
			break;
		if (msg.message == GS_GUI_WIN_MAGIC_MSGNUM_REFRESH)
			InvalidateRect(hwnd, NULL, false);

		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
}

class GuiCtxPlatWin : public GuiCtxPlat
{
public:
	GuiCtxPlatWin(GuiCtx *ctx) :
		m_ctx(ctx),
		m_event0(NULL)
	{
		if (! (m_event0 = CreateEvent(NULL, TRUE, FALSE, NULL)))
			throw std::runtime_error("create event");
	}

	void virtualGuiRun() override {
		/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms644946(v=vs.85).aspx
		     see the Remarks section of linked page for synchronization protocol. */
		MSG msg = {};
		PeekMessage(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);
		if (! SetEvent(m_event0))
			throw std::runtime_error("set event");
		
		win_threadfunc();
	}

	void virtualGuiStopRequest() override {
		sendMessage(GS_GUI_WIN_MAGIC_MSGNUM_QUIT);
	}

	void virtualGuiRefreshRequest() override {
		sendMessage(GS_GUI_WIN_MAGIC_MSGNUM_REFRESH);
	}

protected:
	void sendMessage(UINT msgnum) {
		/* https://msdn.microsoft.com/en-us/library/jj870808(v=vs.120).aspx
		     native_handle_type is defined as a Win32 HANDLE that's cast as void */
		std::thread &thread = m_ctx->getThread();
		HANDLE hthread = (HANDLE) thread.native_handle();
		DWORD idthread = GetThreadId(hthread);

		/* https://msdn.microsoft.com/en-us/library/windows/desktop/ms644946(v=vs.85).aspx
		     "The function fails if the specified thread does not have a message queue."
		     creating message queue races with stop request.
		     see the Remarks section of linked page for synchronization protocol. */
		if (WaitForSingleObject(m_event0, INFINITE) != WAIT_OBJECT_0)
			throw std::runtime_error("wait for single object");
		if (! PostThreadMessage(idthread, msgnum, 0, 0))
			throw std::runtime_error("post thread message");
	}

private:
	ns_gui::GuiCtx *m_ctx;
	HANDLE m_event0;
};

GuiCtxPlat * gui_ctx_plat_create(GuiCtx *ctx)
{
	return new GuiCtxPlatWin(ctx);
}

}
