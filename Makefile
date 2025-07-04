SHELL = /bin/sh
MAIN_NAME=sls
CLIENT_NAME=slc
INC_PATH = -I./ -I../ -I./slscore -I./include
LIB_PATH =  -L ./lib
LIBRARY_FILE = -lpthread -lz -lsrt -lcrypto -lsqlite3
BIN_PATH = ./bin

DEBUG = -g
CFLAGS += $(DEBUG) -w -fcompare-debug-second 

LOG_PATH = ./logs


OUTPUT_PATH = ./obj
OBJS = $(OUTPUT_PATH)/SLSLog.o \
	$(OUTPUT_PATH)/common.o\
	$(OUTPUT_PATH)/conf.o\
	$(OUTPUT_PATH)/SLSThread.o\
	$(OUTPUT_PATH)/SLSEpollThread.o\
	$(OUTPUT_PATH)/SLSManager.o\
	$(OUTPUT_PATH)/SLSGroup.o\
	$(OUTPUT_PATH)/SLSRole.o\
	$(OUTPUT_PATH)/SLSListener.o\
	$(OUTPUT_PATH)/SLSRoleList.o\
	$(OUTPUT_PATH)/SLSSrt.o\
	$(OUTPUT_PATH)/SLSPublisher.o\
	$(OUTPUT_PATH)/SLSPlayer.o\
	$(OUTPUT_PATH)/SLSRecycleArray.o\
	$(OUTPUT_PATH)/SLSMapData.o\
	$(OUTPUT_PATH)/SLSMapPublisher.o\
	$(OUTPUT_PATH)/SLSRelay.o\
	$(OUTPUT_PATH)/SLSPuller.o\
	$(OUTPUT_PATH)/SLSPusher.o\
	$(OUTPUT_PATH)/SLSRelayManager.o\
	$(OUTPUT_PATH)/SLSPullerManager.o\
	$(OUTPUT_PATH)/SLSPusherManager.o\
	$(OUTPUT_PATH)/SLSMapRelay.o\
	$(OUTPUT_PATH)/SLSClient.o\
	$(OUTPUT_PATH)/TCPRole.o\
	$(OUTPUT_PATH)/SLSArray.o\
	$(OUTPUT_PATH)/HttpRoleList.o\
	$(OUTPUT_PATH)/HttpClient.o\
	$(OUTPUT_PATH)/SLSSyncClock.o\
	$(OUTPUT_PATH)/TSFileTimeReader.o\
	$(OUTPUT_PATH)/SLSDatabase.o\
	$(OUTPUT_PATH)/SLSApiServer.o
	
CORE_PATH = slscore
COMMON_FILES = common.hpp

all: $(OBJS)
	mkdir -p ${LOG_PATH}
	mkdir -p ${OUTPUT_PATH}
	mkdir -p ${BIN_PATH}
	${CXX} -o ${BIN_PATH}/${MAIN_NAME}   srt-live-server.cpp $(OBJS) $(CFLAGS) $(INC_PATH) $(LIB_PATH) $(LIBRARY_FILE)
	${CXX} -o ${BIN_PATH}/${CLIENT_NAME} srt-live-client.cpp $(OBJS) $(CFLAGS) $(INC_PATH) $(LIB_PATH) $(LIBRARY_FILE)
	#******************************************************************************#
	#                          Build successful !                                  #
	#******************************************************************************#

$(OUTPUT_PATH)/%.o: ./$(CORE_PATH)/%.cpp
	${CXX} -c $(CFLAGS) $< -o $@ $(INC_PATH)

$(OUTPUT_PATH)/TSFileTimeReader.o: $(CORE_PATH)/TSFileTimeReader.cpp
	$(CXX) -c $(CFLAGS) $< -o $@ $(INC_PATH)

$(OUTPUT_PATH)/SLSDatabase.o: $(CORE_PATH)/SLSDatabase.cpp
	$(CXX) -c $(CFLAGS) $< -o $@ $(INC_PATH)

$(OUTPUT_PATH)/SLSApiServer.o: $(CORE_PATH)/SLSApiServer.cpp
	$(CXX) -c $(CFLAGS) $< -o $@ $(INC_PATH)

clean:
	rm -f $(OUTPUT_PATH)/*.o
	rm -rf $(BIN_PATH)/*

