
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <unistd.h>

#include "fs_list.h"

#define bool char
#define true  1
#define false 0

/*
static const char *fs_list[][3] = {
	{ "a0.jpg", "00", NULL },
	{ "a1.jpg", "01", NULL },
	{ "a2.jpg", "02", NULL },
	{ "a3.jpg", "03", NULL },
	{ "a4.jpg", "04", NULL },
	{ "a5.jpg", "05", NULL },
};
*/
/*
static const char png_head[2][8] = {
	{ 0x89,0x50,0x4E,0x47, 0x0D,0x0A,0x1A,0x0A },
	{ 0x49,0x45,0x4E,0x44, 0xAE,0x42,0x60,0x82 }
};

static const char jpg_head[2][2] = {
	{ 0xFF,0xD8 },
	{ 0xFF,0xD9 }
};

bool fs_isimage(const char *path)
{
	FILE *fs = fopen(path, "rb");
	if   (fs)
	{   static char data[8];
		if(8 == fread(data, 1, 8, fs))
	{   for(int i = 0; i < 8; i++)
		if(data[i] != png_head[0][i]) return false;
		//fseek(fs, 0, SEEK_END);
		//size_t size = ftell(fs);
		//fseek(fs, 0, SEEK_SET);//fseek(fs, size-16, SEEK_SET);
		//if(8 == fread(data, 1, 8, fs))
		return true;
	} }
	return false;
}
*/

#define fs_exist( path) (0 == access(path, F_OK))

/*
t_loop="-loop 1 -t 0.04"
t_font="x=(w/16):y=(h-h/16):fontsize=16:fontcolor=white"
t_fmt="-s 512*512 -c:v libx264 -pix_fmt yuv420p"

t_text="${t_text}[0:v]drawtext=text='a0.jpg':${t_font}[v0];"
t_text="${t_text}[1:v]drawtext=text='a1.jpg':${t_font}[v1];"
t_text="${t_text}[2:v]drawtext=text='a2.jpg':${t_font}[v2];"
t_text="${t_text}[v0][v1][v2]concat=n=3:v=1:a=0[out]"

ffmpeg -y \
	${t_loop} -i a0.jpg \
	${t_loop} -i a1.jpg \
	${t_loop} -i a2.jpg \
	  -filter_complex "${t_text}" -map "[out]" \
    ${t_fmt} ${1}.mp4
*/

#define k_shell_head "#!/system/bin/sh"       \
"\n\nclear"                                   \
"\n\nRootSD=$(cd \"$(dirname \"$0\")\"; pwd)" \
"\n\ncd ${RootSD}\n"                          \
"\nt_loop=\"-loop 1 -t 0.06\""                \
"\nt_font=\"x=(w/16):y=(h-h/16):fontsize=16:fontcolor=white\"" \
"\nt_fmt=\"-s 512*512\""

#define k_ffmpeg_head "\n\nffmpeg -y \\"
#define k_ffmpeg_line "\n\t${t_loop} -i %s \\"
#define k_ffmpeg_end  "\n\t-filter_complex \"${t_text}\" -map \"[out]\" ${t_fmt}"

#define k_ffmpeg_cat "\n"                     \
	"\nrm -f list.txt"                        \
	"\nrm -f ${1}.mp4"                        \
	"\n\nfor fs in $(ls | grep .mp4); do"     \
	"\n\techo file \\\'${fs}\\\' >> list.txt" \
	"\ndone"                                  \
	"\n\nffmpeg -y -f concat -safe 0 -i list.txt -c copy ${1}.mp4" \
	"\n\nrm -f list.txt"

#define OFFSET 100

void gen_shell(const char *path)
{
	FILE *fs = fopen(path, "wb");
	if   (fs)
	{
		fwrite(k_shell_head, strlen(k_shell_head) , 1, fs);
		size_t count = 0, sum = 0, n, i, k, size = sizeof(fs_list) / sizeof(fs_list[0]);
		printf("size: %zu\n", size);

		for(i = 0; i < size; i++) if(fs_exist(fs_list[i][0]))
			{ count++; fs_list[i][2] = fs_list[i][0]; }

		for(n = 0; n < size; n+=OFFSET)
		{
			if(sum >= count) break;

			fprintf(fs, "\n\necho offset: %zu", n/OFFSET);
			fwrite (    "\nt_text=\"\"", 11, 1, fs);
			//printf("idx %zu\n", n);
			k = 0; for(i = n; i < n+OFFSET; i++)
				if(fs_list[i][2])
				{
					//printf ("%zu %s\n", i, fs_list[i][0]);
					fprintf(fs, "\nt_text=\"${t_text}[%zu:v]drawtext=text='%s':${t_font}[v%zu];\"", k, fs_list[i][1], k);
					k++; sum++;
				}
			fwrite("\nt_text=\"${t_text}", 18, 1, fs);
			for(i = 0; i < k; i++) fprintf(fs, "[v%zu]", i);
			fprintf(fs, "concat=n=%zu:v=1:a=0[out]\"", k);

			fwrite(k_ffmpeg_head, strlen(k_ffmpeg_head), 1, fs);

			for(i = n; i < n+OFFSET; i++)
				if(fs_list[i][2])
				{
					//printf ("xxx %zu %s\n", i, fs_list[i][0]);
					fprintf(fs, k_ffmpeg_line, fs_list[i][0]);
				}

			fwrite(k_ffmpeg_end, strlen(k_ffmpeg_end), 1, fs);
			fprintf(fs, " %zu.mp4 >/dev/null 2>/dev/null", n/OFFSET);
		}
		fwrite(k_ffmpeg_cat, strlen(k_ffmpeg_cat), 1, fs);
		fclose(fs);
	}
}

int main(int argc, char **argv)
{
	gen_shell(argv[1]);
	return 0;
}
