#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define true 1
#define false 0

#define PACKET_LENGTH 188
#define SUFFIX "_tspick"

typedef unsigned char byte;

int getpid(const byte *data);
int getseclen(const byte *data);
int find(int value, const int *array, int len);
unsigned int crc32(const byte* data, int len);

int main(int argc, char** argv) {
    FILE *in, *out;
    DIR *dir;
    char *infile, *outfile, *index;
    int pmt = 0, pid;
    int *pids = NULL, pidc = 0;
    byte buf[PACKET_LENGTH];
    byte z[PACKET_LENGTH - 5];
    unsigned int crc;
    int i, Nall, N;

    /* 引数を評価 */
    if (argc == 2) {
        /* 出力先を入力ファイルにサフィックスをつけて自動生成 */
        infile = argv[1];
        outfile = (char *)malloc(strlen(infile) + strlen(SUFFIX) + 1);
        index = strrchr(infile, '.');
        if (index != NULL) {
            *index = '\0';
        }
        strcpy(outfile, infile);
        strcat(outfile, SUFFIX);
        if (index != NULL) {
            *index = '.';
            strcat(outfile, index);
        }
    } else if (argc == 3) {
        /* 出力先指定あり */
        infile = argv[1];
        if ((dir = opendir(argv[2])) == NULL) {
            /* ファイル名を指定 */
            outfile = argv[2];
        } else {
            /* ディレクトリを指定された場合、入力と同じファイル名で作成する */
            closedir(dir);
            index = strrchr(infile, '/');
            if (index == NULL)
                index = infile;
            else
                index++;
            if (argv[2][strlen(argv[2]) - 1] == '/')
                argv[2][strlen(argv[2]) - 1] = '\0';
            outfile = (char *)malloc(strlen(argv[2]) + strlen(index) + 2);
            strcpy(outfile, argv[2]);
            strcat(outfile, "/");
            strcat(outfile, index);
        }
    } else {
        printf("usage: tspick source.ts [dest]\n");
        exit(EXIT_FAILURE);
    }


    /* 抽出するデータの選定 */
    if ((in = fopen(infile, "rb")) == NULL) {
        printf("Can't open input file: %s\n", infile);
        free(outfile);
        exit(EXIT_FAILURE);
    }

    while (true) {
        if (fread(buf, sizeof(byte), PACKET_LENGTH, in) == 0)
            break;

        pid = getpid(buf + 1);

        /* PAT */
        if (pid == 0x0000) {
            pmt = getpid(buf + 19);
            /* PATのPMT1のみ残した差し替えデータを作成 */
            memcpy(z, buf + 5, 16);
            /* セクション長を0x11で上書き */
            z[2] = 0x11;
            /* CRC計算 */
            crc = crc32(z, 16);

            z[16] = (crc >> 24) & 0xFF;
            z[17] = (crc >> 16) & 0xFF;
            z[18] = (crc >> 8) & 0xFF;
            z[19] = crc & 0xFF;
            for (i = 20; i < PACKET_LENGTH - 5; i++)
                z[i] = 0xFF;
        } else if (pid == pmt) {
            /* PMT */
            Nall = getseclen(buf + 6);
            /* 残すPID数を計算 */
            pidc = 2;
            for (N = getseclen(buf + 15) + 16 + 1; N < Nall + 8 - 4; N += 4 + getseclen(buf + N + 3) + 1) {
                if (buf[N] != 0x0D)
                    pidc++;
            }
            pids = (int *)malloc(pidc * sizeof(int));

            /* PIDを配列に格納 */
            pids[0] = pmt;
            /* PCR */
            pids[1] = getpid(buf + 13);
            /* EPID */
            i = 2;
            for (N = getseclen(buf + 15) + 16 + 1; N < Nall + 8 - 4; N += 4 + getseclen(buf + N + 3) + 1) {
                if (buf[N] != 0x0D)
                    pids[i++] = getpid(buf + N + 1);
            }

            printf("Extract pids");
            for (i = 0; i < pidc; i++)
                printf(", 0x%04x", pids[i]);
            printf("\n");
            break;
        }
    }

    /* 入力ファイルの先頭に戻す(入力をfifoにする場合はコメントアウト) */
    fseek(in, 0, SEEK_SET);

    /* ファイル出力 */
    printf("Output file: %s\n", outfile);
    if ((out = fopen(outfile, "wb")) == NULL) {
        printf("Can't open output file\n");
        fclose(in);
        free(outfile);
        free(pids);
        exit(EXIT_FAILURE);
    }

    while (true) {
        if (fread(buf, sizeof(byte), PACKET_LENGTH, in) == 0)
            break;

        pid = getpid(buf + 1);

        /* PAT */
        if (pid == 0x0000) {
            /* 修正後のデータを出力 */
            fwrite(buf, sizeof(byte), 5, out);
            fwrite(z, sizeof(byte), PACKET_LENGTH - 5, out);
        } else if (find(pid, pids, pidc)) {
            fwrite(buf, sizeof(byte), PACKET_LENGTH, out);
        }
    }

    fclose(out);
    fclose(in);
    free(outfile);
    free(pids);

    return EXIT_SUCCESS;
}

int getpid(const byte *data) {
    return ((data[0] & 0x1F) << 8) + data[1];
}

int getseclen(const byte *data) {
    return ((data[0] & 0x0F) << 8) + data[1];
}

int find(int value, const int *array, int len) {
    int i;
    for (i = 0; i < len; i++) {
        if (array[i] == value)
            return true;
    }
    return false;
}

unsigned int crc32(const byte *data, int len) {
    int crc = 0xFFFFFFFF;
    byte bit;
    int c, i;

    for (; len--; data++) {
        for (i = 0; i < 8; i++) {
            bit = (*data >> (7 - i)) & 0x1;
            c = 0;

            if (crc & 0x80000000)
                c = 1;

            crc = crc << 1;

            if (c ^ bit)
                crc ^= 0x04C11DB7;

            crc &= 0xFFFFFFFF;
        }
    }
    return crc;
}
