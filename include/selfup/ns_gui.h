#ifndef _NS_GUI_
#define _NS_GUI_

#include <exception>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#define GS_GUI_FRAMERATE 30

#define GS_GUI_COLOR_MASK_RGB 0x00FF00
#define GS_GUI_COLOR_MASK_BGR 0x00FF00

#define NS_AUX_LOCK() std::lock_guard<std::mutex> lock(g_gui_ctx->getMutex())
#define NS_AUX_PRGS() (g_gui_ctx->getProgress())
#define NS_AUX_RFSH() (g_gui_ctx->refreshRequest())

#define NS_GUI_MODE_RATIO(a, b) do { NS_AUX_LOCK(); NS_AUX_PRGS().progressModeRatio(a, b); NS_AUX_RFSH(); } while(0)
#define NS_GUI_MODE_BLIP()      do { NS_AUX_LOCK(); NS_AUX_PRGS().progressModeBlipAndIncrement(); NS_AUX_RFSH(); } while (0)
#define NS_GUI_STATUS(msg)         do { NS_AUX_LOCK(); NS_AUX_PRGS().progressSetStatus(msg); NS_AUX_RFSH(); } while (0)

namespace ns_gui { class GuiCtx; }
extern std::unique_ptr<ns_gui::GuiCtx> g_gui_ctx;

namespace ns_gui
{

/* needs subclassing per-platform */
class GuiCtxPlat
{
public:
	virtual ~GuiCtxPlat() = default;
	virtual void virtualGuiRun() = 0;
	virtual void virtualGuiStopRequest() = 0;
	virtual void virtualGuiRefreshRequest() = 0;
};
/* needs implementation per-platform */
GuiCtxPlat * gui_ctx_plat_create(GuiCtx *ctx);

class AuxImg
{
public:
	AuxImg() :
		m_name(),
		m_width(0),
		m_height(0),
		m_data()
	{}

	std::string m_name;
	int m_width;
	int m_height;
	std::string m_data;
};

class GuiProgress
{
public:
	GuiProgress() :
		m_mode(0),
		m_ratio_a(0),
		m_ratio_b(0),
		m_blip_cnt(-1),
		m_status()
	{}

	void progressModeRatio(int ratio_a, int ratio_b)
	{
		m_mode = 0;
		m_ratio_a = ratio_a;
		m_ratio_b = ratio_b;
	}

	void progressModeBlipAndIncrement()
	{
		m_mode = 1;
		m_blip_cnt += 1;
	}

	void progressSetStatus(const std::string &status)
	{
		m_status = status;
	}

public:
	int m_mode; /* 0:ratio 1:blip */
	int m_ratio_a, m_ratio_b;
	size_t m_blip_cnt;

	std::string m_status;
};

class GuiCtx
{
public:
	GuiCtx() :
		m_ctxplat(gui_ctx_plat_create(this)),
		m_progress(new GuiProgress()),
		m_mutex(),
		m_thread_exc(),
		m_thread()
	{}

	void threadFunc()
	{
		try {
			m_ctxplat->virtualGuiRun();
		}
		catch (const std::exception &e) {
			m_thread_exc = std::current_exception();
		}
	}

	void start()
	{
		m_thread = std::move(std::thread(&GuiCtx::threadFunc, this));
	}

	void join()
	{
		m_thread.join();

		if (m_thread_exc) {
			try {
				std::rethrow_exception(m_thread_exc);
			}
			catch (const std::exception &e) {
				throw;
			}
		}
	}

	void stopRequest()
	{
		m_ctxplat->virtualGuiStopRequest();
	}

	void refreshRequest()
	{
		m_ctxplat->virtualGuiRefreshRequest();
	}

	std::mutex & getMutex()
	{
		return m_mutex;
	}

	GuiProgress & getProgress()
	{
		return *m_progress;
	}

	std::thread & getThread()
	{
		return m_thread;
	}

	static void initGlobal()
	{
		if (g_gui_ctx)
			throw std::runtime_error("ctx global");
		std::unique_ptr<GuiCtx> ctx(new GuiCtx());
		std::lock_guard<std::mutex> lock(ctx->getMutex());
		g_gui_ctx = std::move(ctx);
	}

private:
	std::unique_ptr<GuiCtxPlat>  m_ctxplat;
	std::unique_ptr<GuiProgress> m_progress;
	std::mutex         m_mutex;
	std::exception_ptr m_thread_exc;
	std::thread        m_thread;
};

AuxImg readimage_data(const std::string & filename, const std::string & data);
AuxImg readimage_file(const std::string & filename);
AuxImg readimage_hex(const std::string & filename, const std::string & hex);

void progress_blip_calc(
	int blip_cnt,
	int img_pb_empty_width, int img_pb_blip_width,
	int * o_src_x, int * o_draw_left, int * o_draw_width);

}

#endif /* _NS_GUI_ */
