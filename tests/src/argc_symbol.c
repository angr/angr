#include <stdio.h>

int main(int argc, char **argv){

    if(argc == 0){
        return 1;
    }

    if(argc == 1){
        if(!strcmp(argv[0],"Good man")) {return 2;}
    }

    if(argc == 2){
        if(!strcmp(argv[1],"Very Good man")) {return 3;}
    }
    
    return 0;
}
