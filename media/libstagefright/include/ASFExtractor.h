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

#ifndef ASF_EXTRACTOR_H_
#define ASF_EXTRACTOR_H_

#include <media/stagefright/foundation/ABase.h>
#include <media/stagefright/MediaExtractor.h>
#include <media/stagefright/MediaSource.h>
#include <media/stagefright/DataSource.h>
#include <media/stagefright/Utils.h>
#include <utils/Vector.h>
#include "asf.h"

namespace android {

///////////////////////////////////////////////////////////////////////////////
// Function Pointer Declaration
typedef int (*asf_init_function)(asf_file_t *);
typedef int (*asf_get_packet_function)(asf_file_t *, asf_packet_t *);
typedef int64_t (*asf_seek_to_msec_function)(asf_file_t *, int64_t);
typedef asf_packet_t * (*asf_packet_create_function)();
typedef int (*asf_packet_destroy_function)(asf_packet_t *);
typedef asf_stream_t *(*asf_get_stream_function)(asf_file_t *, int);
typedef void (*asf_close_function)(asf_file_t *);

struct ASFExtractor : public MediaExtractor {
    ASFExtractor(const sp<DataSource> &dataSource);

    virtual size_t countTracks();

    virtual sp<MediaSource> getTrack(size_t index);

    virtual sp<MetaData> getTrackMetaData(
            size_t index, uint32_t flags);

    virtual sp<MetaData> getMetaData();
    sp<DataSource> mDataSource;
    void *mLibAsfHandle;
protected:
    virtual ~ASFExtractor();

private:
    struct ASFSource;

    struct SampleInfo {
        uint32_t mOffset;
        bool mIsKey;
    };

    struct Track {
        sp<MetaData> mMeta;
        Vector<SampleInfo> mSamples;

        enum Kind {
            AUDIO,
            VIDEO,
            OTHER

        } mKind;

        size_t mNumSyncSamples;
        size_t mThumbnailSampleSize;
        ssize_t mThumbnailSampleIndex;
        size_t mMaxSampleSize;

        double mAvgChunkSize;
        size_t mFirstChunkSize;
        asf_stream_type_t mStreamNumber;
    };

    status_t mInitCheck;
    Vector<Track> mTracks;
    asf_file_t *mFileHandle;
    int32_t mDataPacketPosition;
    bool mIsVC1AdvancedProfile;

    enum TrackTypes {
        AUDIO_TRACK,
        VIDEO_TRACK
    } mTrackType;

    mutable Mutex mLock;

    ssize_t parseChunk(off64_t offset, off64_t size, int depth = 0);
    status_t parseStreamHeader(off64_t offset, size_t size);
    status_t parseStreamFormat(off64_t offset, size_t size);
    status_t parseIndex(off64_t offset, size_t size);

    status_t parseHeaders();

    status_t getPacket(asf_file_t *mFileHandle, asf_packet_t *mPacket);

    status_t getSampleTime(
            size_t trackIndex, size_t sampleIndex, int64_t *sampleTimeUs);

    status_t getSampleIndexAtTime(asf_file_t *mfileHandle, int64_t timeUs);

    status_t addMPEG4CodecSpecificData(size_t trackIndex);
    status_t addH264CodecSpecificData(size_t trackIndex);
    status_t addVC1CodecSpecificData(asf_bitmapinfoheader_t *bmp, sp<MetaData> meta);
    status_t addWMACodecSpecificData(asf_waveformatex_t *wav, sp<MetaData> meta);

    static bool IsCorrectChunkType(
        ssize_t trackIndex, Track::Kind kind, uint32_t chunkType);
    asf_file_t* asfOpenConfigure();
    asf_file_t* asfOpenCb(asf_iostream_t *iostream);

    /////////////////////////////////////////////////////////////////////
    // ASF Library function pointers
    asf_init_function           libasf_init;
    asf_get_packet_function     libasf_get_packet;
    asf_seek_to_msec_function   libasf_seek_to_msec;
    asf_packet_create_function  libasf_packet_create;
    asf_packet_destroy_function libasf_packet_destroy;
    asf_get_stream_function     libasf_get_stream;
    asf_close_function          libasf_close;

    DISALLOW_EVIL_CONSTRUCTORS(ASFExtractor);

};

bool SniffASF(
        const sp<DataSource> &source, String8 *mimeType, float *confidence,
        sp<AMessage> *);

}  // namespace android

#endif  // ASF_EXTRACTOR_H_
