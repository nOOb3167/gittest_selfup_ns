#include <cstddef>
#include <cstdio>

#include <mutex>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>

#include <selfup/ns_filesys.h>
#include <selfup/ns_gui.h>
#include <selfup/ns_helpers.h>    // GS_MAX, decode_hex

std::unique_ptr<ns_gui::GuiCtx> g_gui_ctx;

namespace ns_gui
{

AuxImg readimage_data(const std::string &filename, const std::string &data)
{
	std::vector<std::string> tokens;

	std::stringstream ss(filename);
	std::string item;

	while (std::getline(ss, item, '_'))
		tokens.push_back(item);

	if (tokens.size() < 3)
		std::runtime_error("img tokens");

	AuxImg img;
	img.m_name = tokens[0];
	img.m_width = stoi(tokens[1], NULL, 10);
	img.m_height = stoi(tokens[2], NULL, 10);
	img.m_data = data;

	if (img.m_data.size() != img.m_width * img.m_height * 3)
		std::runtime_error("img size");

	return img;
}

AuxImg readimage_file(const std::string &filename)
{
	return readimage_data(filename, ns_filesys::file_read(filename));
}

AuxImg readimage_hex(const std::string &filename, const std::string &hex)
{
	return readimage_data(filename, decode_hex(hex, false));
}

void progress_blip_calc(
	int blip_cnt,
	int img_pb_empty_width, int img_pb_blip_width,
	int *o_src_x, int *o_draw_left, int *o_draw_width)
{
	/* FIXME: pb_left and pb_right cutoffs are actually designed to be adjustable */
	const float ratio = (float)(blip_cnt % 100) / 100;
	const int blip_left_half = img_pb_blip_width / 2;
	const int blip_right_half = img_pb_blip_width - blip_left_half;
	const int pb_left = 0;                      /*blip cutoff*/
	const int pb_right = img_pb_empty_width;    /*blip cutoff*/
	const int draw_center = img_pb_empty_width * ratio; /*blip center (rel)*/
	int draw_left = draw_center - blip_left_half;
	int draw_cut = GS_MAX(pb_left - draw_left, 0);
	int src_x = 0;
	/* imagine wanting to draw blip at x-plane of 10 (draw_left) but skip
	   everything until 15 (pb_left). you'd want to
	     - start drawing at x-plane 15 (draw_left)
	     - draw pixels of blip higher than 5 (10->15) (src_x)
	   left skip will be done setting draw_left and src_x appropriately
	*/
	src_x = draw_cut;
	draw_left += src_x;
	/* having adjusted draw_left and src_x for left skip, compute right skip
	   note that after the adjustment width of blip essentially changed
	   right skip will be done setting width (draw_width) appropriately */
	int draw_right = draw_center + blip_right_half;
	int draw_cut2 = GS_MAX(draw_right - pb_right, 0);
	int widd_remaining_considering_src_x = img_pb_blip_width - src_x;
	int draw_width = widd_remaining_considering_src_x - draw_cut2;

	if (o_src_x)
		*o_src_x = src_x;
	if (o_draw_left)
		*o_draw_left = draw_left;
	if (o_draw_width)
		*o_draw_width = draw_width;
}

}
