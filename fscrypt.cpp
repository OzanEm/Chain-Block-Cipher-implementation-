
#include "fscrypt.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <vector>

void *fs_encrypt(void *plaintext, int bufsize, char *keystr,int *resultlen){

    //

    BF_KEY* key = (BF_KEY*)malloc(sizeof(BF_KEY));
  	BF_set_key(key, strlen(keystr), (const unsigned char*)keystr);

    unsigned char * text = (unsigned char *) plaintext;
    int padding = bufsize%BLOCKSIZE;
    int blocks = bufsize / BLOCKSIZE;
    blocks++;

    vector<unsigned char*> *Inputs = new vector<unsigned char *>();//holder of blocks
    vector<unsigned char*> *Cipher = new vector<unsigned char *>();//holder of cipher
    vector<unsigned char> Init(BLOCKSIZE,'\0');

    unsigned char * PlText;
    if(padding == 0){
      PlText = new unsigned char(BLOCKSIZE+bufsize);
      for(int i =0;i<bufsize;i++){
        *(PlText+i) = *(text + i);
      }
      for(int i=0;i<BLOCKSIZE;i++){
        *(PlText+i+bufsize) =  (unsigned char) ( ((int)'0') + BLOCKSIZE );
      }

    }else{//
      PlText = new unsigned char(bufsize+ (BLOCKSIZE - (bufsize%BLOCKSIZE) ) );
      for(int i =0;i<bufsize;i++){
        *(PlText+i) = *(text + i);
      }
      for(int i=0;i<(BLOCKSIZE - (bufsize%BLOCKSIZE) );i++){
        *(PlText+i+bufsize) = (unsigned char)(((int)'0') + (BLOCKSIZE - (bufsize%BLOCKSIZE) ) );

      }
    }



    //padding

    for(int i=0;i<blocks;i++){
      unsigned char * ptr = new unsigned char(BLOCKSIZE);

      for(int j=0;j<BLOCKSIZE;j++){

        *(ptr+j) = *(PlText+j+(i*BLOCKSIZE) );
      }
      Inputs->push_back(ptr);
    }


    //Blocks


    for(int i=0;i<blocks;i++){
      unsigned char * ptr = new unsigned char(BLOCKSIZE);
      unsigned char *tmp = new unsigned char(BLOCKSIZE);
      Cipher->push_back(ptr);

      if(i==0){

        for(int j=0;j<BLOCKSIZE;j++){
            *(tmp+j) = Inputs->at(i)[j] ^ Init[j];

          }

        }else{

          for(int j=0;j<BLOCKSIZE;j++){
              *(tmp+j) = Inputs->at(i)[j] ^ Cipher->at(i-1)[j];

            }

        }

        BF_ecb_encrypt( tmp , (*Cipher)[i] , key , BF_ENCRYPT);

    }

    //Encrypt


     int temp=(blocks *BLOCKSIZE);
     *resultlen =temp;

    unsigned char* result = new unsigned char(blocks*BLOCKSIZE);

    for(int i=0;i<blocks;i++){

      for(int j=0;j<BLOCKSIZE;j++){
        *(result+j+(i*BLOCKSIZE)) = Cipher->at(i)[j];
      }

    }

    return (void *) result;

}


void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){

  unsigned char * text = (unsigned char *) ciphertext;
  int blocks = bufsize  / BLOCKSIZE;
  int padding = bufsize%BLOCKSIZE;

  BF_KEY* key = (BF_KEY*)malloc(sizeof(BF_KEY));
  BF_set_key(key, strlen(keystr), (const unsigned char*)keystr);

  vector<unsigned char*> * Cipher = new vector<unsigned char*>();
  vector<unsigned char*> * PlainText = new vector<unsigned char*>();
  vector<unsigned char> Init(BLOCKSIZE,'\0');

  for(int i=0;i<blocks;i++){

    unsigned char * ptr = new unsigned char(BLOCKSIZE);

    for(int j=0;j<BLOCKSIZE;j++){

      *(ptr+j) = *(text+j+(i*BLOCKSIZE) );
    }
    Cipher->push_back(ptr);

  }
  //Blocks


  for(int i=0;i<blocks;i++){

    unsigned char *tmp = new unsigned char(BLOCKSIZE);
    unsigned char *ptr = new unsigned char(BLOCKSIZE);

    if(i==0){

        BF_ecb_encrypt( (*Cipher)[i],ptr  , key , BF_DECRYPT);\

    

      }else{
        BF_ecb_encrypt( (*Cipher)[i],tmp , key , BF_DECRYPT);
        for(int j=0;j<BLOCKSIZE;j++){

            *(ptr+j) = *(tmp+j) ^ Cipher->at(i-1)[j];

          }


      }
      PlainText->push_back(ptr);

  }


    

    unsigned char pad  =  (*PlainText)[blocks-1][BLOCKSIZE-1];

    int resultL =  static_cast<int>(pad);
    resultL = resultL - 48;

    unsigned char* ActualText = new unsigned char(bufsize-resultL);


    for(int i=0;i<blocks;i++){

        for(int j=0;j<BLOCKSIZE;j++){
          if(i == (blocks-1) && j == (BLOCKSIZE - resultL)){
            break;
          }

          *(ActualText+j+(i*BLOCKSIZE)) = PlainText->at(i)[j];

        }

    }


    //De pad

    *resultlen = (bufsize-resultL);

    return (void *) ActualText;

}
