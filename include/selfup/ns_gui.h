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

namespace ns_gui { class GuiCtx; }
extern std::unique_ptr<ns_gui::GuiCtx> g_gui_ctx;

/* gui_run needs implementing per-platform */
void gui_run();

namespace ns_gui
{

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
		m_blip_val_old(0),
		m_blip_val(0),
		m_blip_cnt(-1)
	{}

	void progressSetRatio(int ratio_a, int ratio_b)
	{
		m_mode = 0;
		m_ratio_a = ratio_a;
		m_ratio_b = ratio_b;
	}

public:
	int m_mode; /* 0:ratio 1:blip */
	int m_ratio_a, m_ratio_b;
	int m_blip_val_old, m_blip_val, m_blip_cnt;
};

class GuiCtx
{
public:
	GuiCtx() :
		m_progress(new GuiProgress()),
		m_mutex(),
		m_thread_exc(),
		m_thread()
	{}

	void threadFunc()
	{
		try {
			gui_run();
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

	std::mutex & getMutex()
	{
		return m_mutex;
	}

	GuiProgress & getProgress()
	{
		return *m_progress;
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
