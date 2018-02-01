#ifndef _NS_GUI_
#define _NS_GUI_

#include <string>

#define GS_GUI_FRAMERATE 30

#define GS_GUI_COLOR_MASK_RGB 0x00FF00
#define GS_GUI_COLOR_MASK_BGR 0x00FF00

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

	int m_mode; /* 0:ratio 1:blip */
	int m_ratio_a, m_ratio_b;
	int m_blip_val_old, m_blip_val, m_blip_cnt;
};

}

#endif /* _NS_GUI_ */
