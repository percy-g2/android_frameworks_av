/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "ASFExtractor"
#include <utils/Log.h>
#include <stdio.h>

#include <binder/ProcessState.h>
#include <media/stagefright/foundation/hexdump.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/MediaBuffer.h>
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaDefs.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/Utils.h>

#include "include/ASFExtractor.h"
#include "include/asfint.h"
#include <dlfcn.h>

static int32_t asfFileioReadCbSf(void *iostream,  void *buffer, int32_t size);
static int64_t asfFileioSeekCbSf(void *asf_file, int64_t requiredBitStreamPostion);

namespace android {

static const int32_t kSizeOfVC1Info = 20;
static const int32_t kSizeOfBitmapInfoHeader = 40;
static const int32_t kSizeOfWaveFormatEx = 18;
static const int32_t kSizeOfFrameHeader = 4;

struct ASFExtractor::ASFSource : public MediaSource {
    ASFSource(const sp<ASFExtractor> &extractor, size_t trackIndex);

    virtual status_t start(MetaData *params);
    virtual status_t stop();

    virtual sp<MetaData> getFormat();

    virtual status_t read(
            MediaBuffer **buffer, const ReadOptions *options);

protected:
    virtual ~ASFSource();

private:
    status_t getFirstPacket();
    status_t seekToClosestPosition(int64_t seekTimeUs, MediaSource::ReadOptions::SeekMode mode);

    sp<ASFExtractor> mExtractor;
    size_t mTrackIndex;
    const ASFExtractor::Track &mTrack;
    MediaBufferGroup *mBufferGroup;
    size_t mSampleIndex;
    asf_stream_type_t mStreamNum;
    int32_t mPayloadIndex;
    bool mEndOfStream;
    bool mIsFirstPacket;
    int64_t mTrackTimeStamp;
    int64_t mLastFilePosition;
    asf_packet_t *mPacket;
    int64_t mAccumalatedSize;
    TrackTypes mStreamType;

    DISALLOW_EVIL_CONSTRUCTORS(ASFSource);
};

ASFExtractor::ASFSource::ASFSource(
    const sp<ASFExtractor> &extractor, size_t trackIndex)
    : mExtractor(extractor),
      mTrackIndex(trackIndex),
      mTrack(mExtractor->mTracks.itemAt(trackIndex)),
      mBufferGroup(NULL) {
    mStreamNum = mTrack.mStreamNumber;
    if (mTrack.mKind == Track::AUDIO) {
        mStreamType = AUDIO_TRACK;
    } else if (mTrack.mKind == Track::VIDEO) {
        mStreamType = VIDEO_TRACK;
    }

    mPayloadIndex = 0;
    mEndOfStream = false;
    mIsFirstPacket = true;
    mTrackTimeStamp = 0;
    mLastFilePosition = 0;
    mAccumalatedSize = 0;
    mPacket = NULL;
    mPacket = (*(mExtractor->libasf_packet_create))();
}

ASFExtractor::ASFSource::~ASFSource() {
    if (mBufferGroup) {
        stop();
    }

    if (NULL != mPacket) {
        (*(mExtractor->libasf_packet_destroy))(mPacket);
    }
}

status_t ASFExtractor::ASFSource::start(MetaData *params) {
    CHECK(!mBufferGroup);

    mBufferGroup = new MediaBufferGroup;
    mBufferGroup->add_buffer(new MediaBuffer(mTrack.mMaxSampleSize));
    mBufferGroup->add_buffer(new MediaBuffer(mTrack.mMaxSampleSize));
    mSampleIndex = 0;

    const char *mime;
    CHECK(mTrack.mMeta->findCString(kKeyMIMEType, &mime));
    return OK;
}

status_t ASFExtractor::ASFSource::stop() {
    CHECK(mBufferGroup);

    delete mBufferGroup;
    mBufferGroup = NULL;
    return OK;
}

sp<MetaData> ASFExtractor::ASFSource::getFormat() {
    return mTrack.mMeta;
}

////////////////////////////////////////////////////////
// Read the packet from the stream when read() is called
// for the first time
status_t ASFExtractor::ASFSource::getFirstPacket() {
    status_t err;

    // Retrieve the first packet for the specific Track
    do {
        // Read the packet from the current file position
        err = mExtractor->getPacket(mExtractor->mFileHandle, this->mPacket);
        if (err != OK) {
            return ERROR_END_OF_STREAM;
        }

        // Search for the specific payload within the Data Packet
        for (int32_t i = 0; i < this->mPacket->payload_count; i++) {
            if (this->mPacket->payloads[i].stream_number == this->mStreamNum
                                                     && this->mIsFirstPacket) {
                this->mIsFirstPacket = false;
                this->mPayloadIndex = i;
            }
        }

    } while (this->mIsFirstPacket);

    return OK;
}

//////////////////////////////////////////////////////////
// This implementation handles 3 different seek modes and
// SEEK_CLOSEST_SYNC is the default
status_t ASFExtractor::ASFSource::seekToClosestPosition
            (int64_t seekTimeUs, MediaSource::ReadOptions::SeekMode mode) {
    status_t err;
    int32_t  prevKeyIdx;
    int64_t  prevKeyDataPosition;
    int64_t  prevKeytimeUs;
    int32_t  nextKeyIdx;
    bool     isPrevKeyFound, isNextKeyFound;
    int64_t  nextKeyDataPosition;
    int64_t  nextKeytimeUs;
    int64_t  finalKeytimeUs;
    int64_t  currentOffsetPosn;
    int64_t  finalOffsetPosn;
    int32_t  finalKeyIdx;
    bool     iskeyCheckNotRequired = false;

    // Initializations
    prevKeyIdx = nextKeyIdx = 0;
    prevKeyDataPosition = nextKeyDataPosition = mExtractor->mFileHandle->iostream.bit_stream_position;
    prevKeytimeUs = nextKeytimeUs = finalKeytimeUs = seekTimeUs;
    isPrevKeyFound = isNextKeyFound = false;
    finalOffsetPosn = mExtractor->mFileHandle->iostream.bit_stream_position;
    finalKeyIdx = 0;

    ALOGV("ASFSource::seekToClosestPosition: ENTRY");
    if (mStreamType == AUDIO_TRACK) {
        iskeyCheckNotRequired = true;
    }

    // Retrieve the first packet for the specific Track
    do {
        // Read the current offset position inside the file
        currentOffsetPosn = mExtractor->mFileHandle->iostream.bit_stream_position;

        // Read the packet from the current file position
        err = mExtractor->getPacket(mExtractor->mFileHandle, this->mPacket);
        if (err != OK) {
            break;
        }

        // Search for the specific payload within the Data Packet
        for (int32_t i = 0; i < this->mPacket->payload_count; i++) {
            if (this->mPacket->payloads[i].stream_number == this->mStreamNum &&
                    (this->mPacket->payloads[i].key_frame || iskeyCheckNotRequired)) {
                if (this->mPacket->payloads[i].pts * 1000 != prevKeytimeUs &&
                        this->mPacket->payloads[i].pts * 1000 <= seekTimeUs) {
                    // Case when the timestamp of the key frame is
                    // less than or equal to desired timestamp
                    prevKeyIdx = i;
                    prevKeyDataPosition = currentOffsetPosn;
                    prevKeytimeUs = this->mPacket->payloads[i].pts;
                    isPrevKeyFound = true;
                    ALOGV("Prev Sync TimeStamp: %lld, prevKeyDataPosition: %lld",
                            prevKeytimeUs, prevKeyDataPosition);
                } else {
                    // Case when the timestamp is greater than requested time stamp
                    if (!isNextKeyFound) {
                        nextKeyIdx = i;
                        nextKeyDataPosition = currentOffsetPosn;
                        nextKeytimeUs = this->mPacket->payloads[i].pts;
                        isNextKeyFound = true;
                        ALOGV("Next Sync TimeStamp: %lld, nextKeyDataPosition: %lld",
                                nextKeytimeUs, nextKeyDataPosition);
                    }
                }
            }
        }
    } while (!isNextKeyFound);

    if (!isNextKeyFound && !isPrevKeyFound) {
        return ERROR_END_OF_STREAM;
    } else if (!isNextKeyFound && isPrevKeyFound) {
        finalOffsetPosn = prevKeyDataPosition;
        finalKeyIdx = prevKeyIdx;
        finalKeytimeUs  = prevKeytimeUs;
    } else {

        // The timestamps of the previous and next key frames are available
        // The parser has to decide between the 2 timestamps
        switch (mode) {
            case MediaSource::ReadOptions::SEEK_CLOSEST_SYNC:
                ALOGV("SEEK_CLOSEST_SYNC");
                if (seekTimeUs - prevKeytimeUs < nextKeytimeUs - seekTimeUs) {
                    if (isPrevKeyFound) {
                        finalOffsetPosn = prevKeyDataPosition;
                        finalKeyIdx     = prevKeyIdx;
                        finalKeytimeUs  = prevKeytimeUs;
                    }
                } else {
                    if (isNextKeyFound) {
                        finalOffsetPosn = nextKeyDataPosition;
                        finalKeyIdx     = nextKeyIdx;
                        finalKeytimeUs  = nextKeytimeUs;
                    }
                }
            break;

            case MediaSource::ReadOptions::SEEK_PREVIOUS_SYNC:
                ALOGV("SEEK_PREVIOUS_SYNC");
                if (isPrevKeyFound) {
                    finalOffsetPosn = prevKeyDataPosition;
                    finalKeyIdx     = prevKeyIdx;
                    finalKeytimeUs  = prevKeytimeUs;
                }
            break;

            case MediaSource::ReadOptions::SEEK_NEXT_SYNC:
                ALOGV("SEEK_NEXT_SYNC");
                if (isNextKeyFound) {
                    finalOffsetPosn = nextKeyDataPosition;
                    finalKeyIdx     = nextKeyIdx;
                    finalKeytimeUs  = nextKeytimeUs;
                }
            break;

            default:
                ALOGV("Default Case");
                if (seekTimeUs - prevKeytimeUs < nextKeytimeUs - seekTimeUs) {
                    if (isPrevKeyFound) {
                        finalOffsetPosn = prevKeyDataPosition;
                        finalKeyIdx     = prevKeyIdx;
                        finalKeytimeUs  = prevKeytimeUs;
                    }
                } else {
                    if (isNextKeyFound) {
                        finalOffsetPosn = nextKeyDataPosition;
                        finalKeyIdx     = nextKeyIdx;
                        finalKeytimeUs  = nextKeytimeUs;
                    }
                }
            break;
        }
    }

    // Decide on finalOffsetPosn, finalKeyIdx
    this->mLastFilePosition = finalOffsetPosn;

    // Seek to appropriate packet and set the index
    mExtractor->mFileHandle->iostream.seek(mExtractor->mFileHandle, this->mLastFilePosition);
    this->mPayloadIndex = finalKeyIdx;
    this->mTrackTimeStamp = finalKeytimeUs;
    ALOGV("finalOffsetPosn: %lld, finalKeyIdx: %d, finalKeytimeUs: %lld",
            finalOffsetPosn, finalKeyIdx, finalKeytimeUs);
    err = mExtractor->getPacket(mExtractor->mFileHandle, this->mPacket);
    if (err != OK) {
        return ERROR_END_OF_STREAM;
    }

    ALOGV("ASFSource::seekToClosestPosition: EXIT");
    return OK;
}

//////////////////////////////////////////////////////////////////////////
// Read multiple data packets until we get the complete frame data.
// Handles different cases based on the fact that the one media frame data
// can be part of different data packets.
status_t ASFExtractor::ASFSource::read(
        MediaBuffer **buffer, const ReadOptions *options) {

    Mutex::Autolock autoLock(mExtractor->mLock);
    CHECK(mBufferGroup);

    *buffer = NULL;

    int64_t seekTimeUs;
    int32_t lFrameSize, lKeyFrame;
    int64_t lCurrPts;
    status_t err;
    bool packetFound;
    ReadOptions::SeekMode seekMode;

    if (this->mEndOfStream) {
        return ERROR_END_OF_STREAM;
    }

    // Restore the position for the current track
    if (this->mIsFirstPacket) {
        this->mLastFilePosition = mExtractor->mDataPacketPosition;
    }
    mExtractor->mFileHandle->iostream.seek(mExtractor->mFileHandle, this->mLastFilePosition);

    if (options && options->getSeekTo(&seekTimeUs, &seekMode)) {
        // libasf works on mses
        do {
            err = mExtractor->getSampleIndexAtTime(mExtractor->mFileHandle, seekTimeUs / 1000);
            if (err != OK) {
                seekTimeUs = seekTimeUs - 1000000;
            }
        } while (err != OK);

        this->mPayloadIndex = 0;
        this->mAccumalatedSize = 0;

        err = this->seekToClosestPosition(seekTimeUs, seekMode);
        if (err != OK) {
            return err;
        }

        ALOGV("Seek is successful!!!");
        this->mIsFirstPacket = false;
    }

    // Case when the read is called for the very first packet
    if (this->mIsFirstPacket) {
        err = this->getFirstPacket();
        if (err != OK) {
            return err;
        }
    }

    // Read the framesize, current PTS, Key frame status from Data Packet
    lFrameSize = this->mPacket->payloads[this->mPayloadIndex].media_object_length;
    lCurrPts = this->mPacket->payloads[this->mPayloadIndex].pts;
    lKeyFrame = this->mPacket->payloads[this->mPayloadIndex].key_frame;
    ALOGV("Stream No: %d, lFrameSize: %d, lCurrPts: %lld, lKeyFrame: %d",
            (int32_t)this->mPacket->payloads[this->mPayloadIndex].stream_number,
            lFrameSize, lCurrPts, lKeyFrame);

    MediaBuffer *out;
    CHECK_EQ(mBufferGroup->acquire_buffer(&out), (status_t)OK);
    uint8_t *framePointer = (uint8_t *)((int32_t)out->data());
    int32_t frameSize = lFrameSize;

    //Appending Frame Header prior to frame data in case of VC1 Adv profile only
    if (mExtractor->mIsVC1AdvancedProfile && mStreamType == VIDEO_TRACK) {
        uint8_t frameHeader[] = {0x00, 0x00, 0x01, 0x0d};
        memcpy(out->data(), frameHeader, kSizeOfFrameHeader);
        framePointer = (uint8_t *)out->data() + kSizeOfFrameHeader;
        frameSize += kSizeOfFrameHeader;
    }
    do {
        // Copy Payload data to Media Buffer
        for (int32_t i = this->mPayloadIndex; i < this->mPacket->payload_count; i++) {
            if (this->mPacket->payloads[i].stream_number == this->mStreamNum) {
                if (this->mPacket->payloads[i].pts != lCurrPts) {
                    this->mPayloadIndex = i;
                    out->set_range(0, frameSize);
                    // Converting to ms to us
                    out->meta_data()->setInt64(kKeyTime, lCurrPts * 1000);
                    if (lKeyFrame) {
                        out->meta_data()->setInt32(kKeyIsSyncFrame, 1);
                    }
                    *buffer = out;

                    this->mAccumalatedSize = 0;
                    this->mTrackTimeStamp = this->mPacket->payloads[this->mPayloadIndex].pts;

                    // Save the file position for the current trackbefore we exit from the loop
                    this->mLastFilePosition = mExtractor->mFileHandle->iostream.bit_stream_position;
                    return OK;
                }
                memcpy(framePointer + this->mAccumalatedSize,
                        this->mPacket->payloads[i].data, this->mPacket->payloads[i].datalen);
                this->mAccumalatedSize += this->mPacket->payloads[i].datalen;
            }
        }

        // Read the next payload
        packetFound = false;
        do {
            err = mExtractor->getPacket(mExtractor->mFileHandle, this->mPacket);
            if (err != OK) {
                this->mEndOfStream = true;
                out->release();
                out = NULL;
                ALOGV("getPacket is failed in read Implementation, Media Buffer release is done!!!");
                return ERROR_END_OF_STREAM;
            }

            for (int32_t i = 0; i < this->mPacket->payload_count; i++) {
                if (this->mPacket->payloads[i].stream_number == this->mStreamNum &&
                        !packetFound) {
                    packetFound = true;
                    this->mPayloadIndex = i;
                }
            }
        } while (!packetFound);
    } while (this->mAccumalatedSize < lFrameSize);

    out->set_range(0, frameSize);
    // Converting to ms to us
    out->meta_data()->setInt64(kKeyTime, lCurrPts * 1000);
    if (lKeyFrame) {
        out->meta_data()->setInt32(kKeyIsSyncFrame, 1);
    }
    *buffer = out;

    // Reset the frame statistics
    this->mAccumalatedSize = 0;
    // Save the file position for the current trackbefore we exit from the loop
    this->mLastFilePosition = mExtractor->mFileHandle->iostream.bit_stream_position;
    ALOGV("EXIT 2: Fragmented Frame Completed for %lld, mLastFilePosition: %lld",
            lCurrPts, this->mLastFilePosition);
    return OK;
}

ASFExtractor::ASFExtractor(const sp<DataSource> &dataSource)
   : mDataSource(dataSource), mFileHandle(NULL), mIsVC1AdvancedProfile(false){
     mInitCheck = parseHeaders();

    if (mInitCheck != OK) {
        mTracks.clear();
    }
}

ASFExtractor::~ASFExtractor() {
    (*libasf_close)(mFileHandle);
    dlclose(mLibAsfHandle);
}

size_t ASFExtractor::countTracks() {
    return mTracks.size();
}

sp<MediaSource> ASFExtractor::getTrack(size_t index) {
    return index < mTracks.size() ? new ASFSource(this, index) : NULL;
}

sp<MetaData> ASFExtractor::getTrackMetaData(
        size_t index, uint32_t flags) {
    return index < mTracks.size() ? mTracks.editItemAt(index).mMeta : NULL;
}

sp<MetaData> ASFExtractor::getMetaData() {
    sp<MetaData> meta = new MetaData;

    if (mInitCheck == OK) {
        meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_CONTAINER_ASF);
    }

    return meta;
}

int32_t asfFileioReadCbSf(void *iostream, void *buffer, int32_t size) {
    asf_iostream_t *lIostream;

    // Get the ASF Extractor object
    lIostream = (asf_iostream_t *)iostream;
    ASFExtractor *pExtractor = (ASFExtractor *)(lIostream->data_source_handle);

    ssize_t bytesRead = pExtractor->mDataSource->readAt(lIostream->bit_stream_position, buffer, size);

    if (bytesRead < (ssize_t)size) {
        return ERROR_MALFORMED;
    }
    lIostream->bit_stream_position += size;
    return bytesRead;
}

int64_t asfFileioSeekCbSf(void *asf_file, int64_t requiredBitStreamPostion) {
    asf_file_t *lASFFile;

    lASFFile = (asf_file_t *)asf_file;
    lASFFile->iostream.bit_stream_position = requiredBitStreamPostion;
    return 0;
}

asf_file_t* ASFExtractor::asfOpenConfigure() {
    asf_file_t *file;
    asf_iostream_t stream;

    stream.read = asfFileioReadCbSf;
    stream.seek = asfFileioSeekCbSf;
    stream.write = NULL;
    stream.opaque = NULL;

    file = asfOpenCb(&stream);
    if (file == NULL) {
        return NULL;
    }

    return file;
}

asf_file_t* ASFExtractor::asfOpenCb(asf_iostream_t *iostream) {
    asf_file_t *file;
    int i;
    if (iostream == NULL)
        return NULL;

    file = (asf_file_t *)calloc(1, sizeof(asf_file_t));
    if (file == NULL) {
        return NULL;
    }

    file->filename = NULL;
    file->iostream.read = iostream->read;
    file->iostream.write = iostream->write;
    file->iostream.seek = iostream->seek;
    file->iostream.opaque = iostream->opaque;
    file->iostream.bit_stream_position = 0;

    file->header = NULL;
    file->data = NULL;
    file->index = NULL;

    for (i = 0; i < ASF_MAX_STREAMS; i++) {
        file->streams[i].type = ASF_STREAM_TYPE_NONE;
        file->streams[i].flags = ASF_STREAM_FLAG_NONE;
        file->streams[i].properties = NULL;
        file->streams[i].extended_properties = NULL;
    }

    return file;
}

/////////////////////////////////////////////////////////////////////
// This function has implementation of 'dynamic linking' to libasf.so
// from Android Multimedia Framework.
// Parse the stream for headers using libasf implementations.
// Formation of Media Tracks based on stream types and pushing the
// same into track list.
// Formation of codec specific data:
// BITMAPINFOHEADER for VC-1 codec
// WAVEFORMATEXT for wma codec

status_t ASFExtractor::parseHeaders() {
    bool isAudioTrackFound = false, isVideoTrackFound = false;

    mLibAsfHandle = dlopen("/system/lib/libasf.so", RTLD_NOW);
    if (mLibAsfHandle == NULL) {
        return ERROR_MALFORMED;
    }

    libasf_init = (asf_init_function)(dlsym(mLibAsfHandle, "asf_init"));
    if (libasf_init == NULL) {
        ALOGV("dlopen of libasf.so is failed!!!");
        return ERROR_MALFORMED;
    }

    libasf_get_packet = (asf_get_packet_function)(dlsym(mLibAsfHandle, "asf_get_packet"));
    if (libasf_get_packet == NULL) {
        return ERROR_MALFORMED;
    }

    libasf_get_stream = (asf_get_stream_function)(dlsym(mLibAsfHandle, "asf_get_stream"));
    if (libasf_get_stream == NULL) {
        return ERROR_MALFORMED;
    }

    libasf_packet_create = (asf_packet_create_function)(dlsym(mLibAsfHandle, "asf_packet_create"));
    if (libasf_packet_create == NULL) {
        return ERROR_MALFORMED;
    }

    libasf_packet_destroy = (asf_packet_destroy_function)(dlsym(mLibAsfHandle, "asf_packet_destroy"));
    if (libasf_packet_destroy == NULL) {
        return ERROR_MALFORMED;
    }

    libasf_seek_to_msec = (asf_seek_to_msec_function)(dlsym(mLibAsfHandle, "asf_seek_to_msec"));
    if (libasf_seek_to_msec == NULL) {
        return ERROR_MALFORMED;
    }
    libasf_close = (asf_close_function)(dlsym(mLibAsfHandle, "asf_close"));
    if (libasf_close == NULL) {
        return ERROR_MALFORMED;
    }

    mTracks.clear();
    mFileHandle = asfOpenConfigure();
    if (mFileHandle == NULL) {
        return ERROR_MALFORMED;
    }

    // Initialize the data handle
    mFileHandle->iostream.data_source_handle = (int)(this);

    ssize_t res = (*libasf_init)(mFileHandle);
    if (res < 0) {
        return ERROR_MALFORMED;
    }

    ALOGV("Stream Size: %lld", mFileHandle->file_size);
    asf_stream_t *stream = NULL;

    for (int i = 0; i < ASF_MAX_STREAMS; i++) {
        stream = (*libasf_get_stream)(mFileHandle, i);
        if (stream == NULL) {
            return ERROR_MALFORMED;
        }

        Track::Kind kind = Track::OTHER;

        if (stream->type == ASF_STREAM_TYPE_AUDIO) {
            ALOGV("Audio Track Found");
            sp<MetaData> meta = new MetaData;
            kind = Track::AUDIO;
            asf_waveformatex_t *wav = (asf_waveformatex_t *)stream->properties;
            const char *mime = NULL;
            mime = MEDIA_MIMETYPE_AUDIO_WMA;
            meta->setCString(kKeyMIMEType, mime);
            meta->setInt32(kKeyChannelCount, wav->nChannels);
            meta->setInt32(kKeySampleRate, wav->nSamplesPerSec);
            addWMACodecSpecificData(wav, meta);
            int64_t durationUs;
            durationUs = mFileHandle->play_duration / 10;
            ALOGV("Audio Track duration = %.2f secs", durationUs / 1E6);
            meta->setInt64(kKeyDuration, durationUs);
            mTracks.push();

            Track *track = &mTracks.editItemAt(mTracks.size() - 1);
            track->mMeta = meta;
            track->mKind = kind;
            track->mNumSyncSamples = 0;
            track->mThumbnailSampleSize = 0;
            track->mThumbnailSampleIndex = -1;
            track->mAvgChunkSize = 1.0;
            track->mFirstChunkSize = 0;
            track->mMaxSampleSize = 65536;
            track->mStreamNumber = (asf_stream_type_t)i;
            isAudioTrackFound = true;
        } else if (stream->type == ASF_STREAM_TYPE_VIDEO) {
            ALOGV("Video Track Found");
            sp<MetaData> meta = new MetaData;
            kind = Track::VIDEO;
            asf_bitmapinfoheader_t *bmp = (asf_bitmapinfoheader_t *)stream->properties;
            const char *mime = NULL;
            mime = MEDIA_MIMETYPE_VIDEO_VC1;
            meta->setCString(kKeyMIMEType, mime);
            status_t err = addVC1CodecSpecificData(bmp, meta);
            if (err != OK) {
                return ERROR_MALFORMED;
            }
            int64_t durationUs;
            durationUs = mFileHandle->play_duration / 10;
            ALOGE("Track duration = %lld us %.2f secs", durationUs, durationUs / 1E6);
            meta->setInt64(kKeyDuration, durationUs);

            mTracks.push();
            Track *track = &mTracks.editItemAt(mTracks.size() - 1);
            track->mMeta = meta;
            track->mKind = kind;
            track->mNumSyncSamples = 0;
            track->mThumbnailSampleSize = 0;
            track->mThumbnailSampleIndex = -1;

            if (NULL != stream->extended_properties) {
                track->mMaxSampleSize = stream->extended_properties->max_obj_size;
            } else {
                size_t lInputBufferSize = (bmp->biWidth * bmp->biHeight * 3) >> 1;
                track->mMaxSampleSize = lInputBufferSize;
            }

            if (mIsVC1AdvancedProfile) {
                track->mMaxSampleSize += kSizeOfFrameHeader;
            }

            track->mAvgChunkSize = 1.0;
            track->mFirstChunkSize = 0;
            track->mStreamNumber = (asf_stream_type_t)i;
            isVideoTrackFound = true;
        }

        if (isVideoTrackFound && isAudioTrackFound) {
            break;
        }
    }

    mDataPacketPosition = mFileHandle->position;
    return OK;
}

status_t ASFExtractor::getSampleIndexAtTime(asf_file_t *fileHandle, int64_t timeUs) {
    if (NULL == fileHandle) {
        return ERROR_MALFORMED;
    }

    status_t err = (*libasf_seek_to_msec)(fileHandle, timeUs);
    if (err < 0) {
        ALOGV("ASF file Seek Failed");
        return ERROR_MALFORMED;
    }

    return OK;
}

status_t ASFExtractor::getPacket(asf_file_t *mFileHandle, asf_packet_t *mPacket) {
    int32_t err;
    err = (*libasf_get_packet)(mFileHandle, mPacket);
    if (err < 0) {
        ALOGV("ASF Get data packet Failed");
        return ERROR_MALFORMED;
    }

    return OK;
}

///////////////////////////////////////////////////////////////////
// For VC-1 Simple (0x0) and Main Profiles (0x4) populate
// STRUCT_C(Sc) and STRUCT_A(Sa) information packed as shown below
// 20 Bytes of header info:
// 00  00  00  00  00  00  00  00
// Sc0 Sc1 Sc2 Sc3 Sa0 Sa1 Sa2 Sa3
// Sa4 Sa5 Sa6 Sa7
//
// VC-1 Advanced Profile:
// If FourCC is WVC1, Concatenating Sequence Header Data and Entry Point Header Data,
// Passing the same as Codec Specific Data to Underlying decoder
status_t ASFExtractor::addVC1CodecSpecificData(asf_bitmapinfoheader_t *bmp, sp<MetaData> meta) {
    uint32_t width, height;
    uint32_t fourCC = U32_AT((uint8_t *)&bmp->biCompression);

    width  = bmp->biWidth;
    height = bmp->biHeight;
    meta->setInt32(kKeyWidth, width);
    meta->setInt32(kKeyHeight, height);

    // fourCC is WMV3 for VC-1 Simple/Main Profile streams
    if (fourCC == FOURCC('W', 'M', 'V', '3') || fourCC == FOURCC('w', 'm', 'v', '3')) {
        ALOGV("VC-1 Simple/Main Profile");

        uint8_t extraData[kSizeOfVC1Info];
        memset(extraData,0,kSizeOfVC1Info);

        if (bmp->biSize - ASF_BITMAPINFOHEADER_SIZE < 4) {
            return ERROR_MALFORMED;
        }

        // Copying 4 bytes of extra data
        for (int i = 0; i < 4 ; i++) {
            extraData[i + 8] = bmp->data[i];
        }

        int32_t height_le = U32LE_AT((uint8_t *)&height);
        memcpy(&extraData[12], &height_le, 4);
        int32_t width_le = U32LE_AT((uint8_t *)&width);
        memcpy(&extraData[16], &width_le, 4);

        meta->setData(kKeyVC1Info, kTypeVC1, extraData, kSizeOfVC1Info);
    } else if (fourCC == FOURCC('W', 'V', 'C', '1') || fourCC == FOURCC('w', 'v', 'c', '1')) {
        ALOGV("VC-1 Advanced Profile");
        mIsVC1AdvancedProfile = true;
        // Total size of Sequence Header and Entry Point header:
        // Subtracting 40 bytes of BITMAPINFOHEADER & One byte for ASF Binding byte
        // from 'Format Data Size'
        int32_t codecSpecificDataSize = bmp->biSize - kSizeOfBitmapInfoHeader - 1;
        meta->setData(kKeyVC1Info, kTypeVC1, bmp->data + 1, codecSpecificDataSize);
    }

    return OK;
}

////////////////////////////////////////////////////////////////////
// Formation of codec specific data of wma decoder:
// Memcpy of bitmapinfoheader fields followed by header info into a
// single buffer.
status_t ASFExtractor::addWMACodecSpecificData(asf_waveformatex_t *wav, sp<MetaData> meta) {
    uint8_t *waveformatex;

    waveformatex = (uint8_t *)malloc(kSizeOfWaveFormatEx + wav->cbSize);

    memcpy(waveformatex, wav, kSizeOfWaveFormatEx);
    memcpy((waveformatex + kSizeOfWaveFormatEx), wav->data, wav->cbSize);

    meta->setData(kKeyWMAInfo, kTypeWMA, waveformatex, kSizeOfWaveFormatEx + wav->cbSize);
    free(waveformatex);
    return OK;
}

bool SniffASF(
        const sp<DataSource> &source, String8 *mimeType, float *confidence,
        sp<AMessage> *) {
    char tmp[16];
    // GUID of ASF Header Object
    char ASF_Header_Object[16] = {0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
                                  0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c };
    if (source->readAt(0, tmp, 16) < 16) {
        return false;
    }

    if (!memcmp(tmp, ASF_Header_Object, 16)) {
        mimeType->setTo(MEDIA_MIMETYPE_CONTAINER_ASF);
        *confidence = 0.7;
        return true;
    }

    return false;
}

}
