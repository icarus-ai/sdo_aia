
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

#define fs_exist( path) (0 == access(path, F_OK))

/*
complex="${complex}[0:v]drawtext=text='a0.jpg':x=10:y=10:fontsize=24:fontcolor=white[v0];"
complex="${complex}[1:v]drawtext=text='a1.jpg':x=10:y=10:fontsize=24:fontcolor=white[v1];"
complex="${complex}[2:v]drawtext=text='a2.jpg':x=10:y=10:fontsize=24:fontcolor=white[v2];"
complex="${complex}[3:v]drawtext=text='a3.jpg':x=10:y=10:fontsize=24:fontcolor=white[v3];"
complex="${complex}[4:v]drawtext=text='a4.jpg':x=10:y=10:fontsize=24:fontcolor=white[v4];"
complex="${complex}[5:v]drawtext=text='a5.jpg':x=10:y=10:fontsize=24:fontcolor=white[v5];"
complex="${complex}[v0][v1][v2][v3][v4][v5]concat=n=6:v=1:a=0[out]"

ffmpeg -y \
  -loop 1 -t 0.5 -i a0.jpg \
  -loop 1 -t 0.5 -i a1.jpg \
  -loop 1 -t 0.5 -i a2.jpg \
  -loop 1 -t 0.5 -i a3.jpg \
  -loop 1 -t 0.5 -i a4.jpg \
  -loop 1 -t 0.5 -i a5.jpg \
  -filter_complex "${complex}" -map "[out]" \
    -c:v libx264 -pix_fmt yuv420p \
    -s 512*512 ${1}.mp4
*/

#define k_shell_head "#!/system/bin/sh"       \
"\n\nclear"                                   \
"\n\nRootSD=$(cd \"$(dirname \"$0\")\"; pwd)" \
"\n\ncd ${RootSD}\n"                          \
"\nt_loop=\"-loop 1 -t 0.5\""                 \
"\nt_fmt=\"-s 512*512\""

// -c:v libx264 -pix_fmt yuv420p 

#define k_ffmpeg_head  "\n\nffmpeg -y \\"
#define k_ffmpeg_line  "\n\t${t_loop} -i %s \\"
#define k_ffmpeg_end   "\n\t-filter_complex \"${complex}\" -map \"[out]\" ${t_fmt}"

#define k_ffmpeg_cat "\n"                     \
	"\nrm -f list.txt"                        \
	"\nrm -f ${1}.mp4"                        \
	"\n\nfor fs in $(ls | grep .mp4); do"     \
	"\n\techo file \\\'${fs}\\\' >> list.txt" \
	"\ndone"                                  \
	"\n\nffmpeg -y -f concat -safe 0 -i list.txt -c copy ${1}.mp4" \
	"\n\nrm -f list.txt"                        \

#define OFFSET 50

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

			fwrite("\n\ncomplex=\"\"", 12, 1, fs);
			//printf("idx %zu\n", n);
			k = 0; for(i = n; i < n+OFFSET; i++)
				if(fs_list[i][2])
				{
					//printf ("%zu %s\n", i, fs_list[i][0]);
					fprintf(fs, "\ncomplex=\"${complex}[%zu:v]drawtext=text='%s':x=(w/16):y=(h-h/16):fontsize=64:fontcolor=white[v%zu];\"", k, fs_list[i][1], k);
					k++; sum++;
				}
			fwrite("\ncomplex=\"${complex}", 20, 1, fs);
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
			fprintf(fs, " %zu.mp4", n/OFFSET);
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

