#include <stdio.h>
#include <stdlib.h>
#include <string.h>




int main(int argc, char const *argv[])
{
    char *iname = NULL;
    int time_packets = 0;
    int count_packets = 0;
    char *filename = NULL;
    
    for (size_t i = 1; i < argc; i++)
    {
        if(strcmp(argv[i],"-i")==0) {
            if(argc>i+1){
                iname = argv[i+1];
                i++;
            }
        }
        else if(strcmp(argv[i],"-f")==0) {
            if(argc>i+1){
                filename = argv[i+1];
                i++;
            }
        }
        else if(strcmp(argv[i],"-t")==0) {
                if(argc>i+1){
                    char *time = argv[i+1];
                    time_packets = atoi(time);
                    i++;
                    continue;
                }
        }
        else if(strcmp(argv[i],"-c")==0) {
                if(argc>i+1){
                    char *count = argv[i+1];
                    count_packets = atoi(count);
                    i++;
                    continue;
                }
        }
    }
    
    printf("interface: %s, time: %d, count packets: %d, filename: %s\n", iname, time_packets, count_packets, filename);
    return 0;
}
