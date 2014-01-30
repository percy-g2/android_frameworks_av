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
#define LOG_TAG "SurfaceMediaSource"

#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/SurfaceMediaSource.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/MediaDefs.h>
#include <OMX_IVCommon.h>
#include <MetadataBufferType.h>

#include <ui/GraphicBuffer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/IGraphicBufferAlloc.h>
#include <OMX_Component.h>

#include <utils/Log.h>
#include <utils/String8.h>

#include <private/gui/ComposerService.h>

#include <ui/GraphicBufferMapper.h>
#include <ui/Region.h>
#include <hardware/hardware.h>
#include <ui/PixelFormat.h>

#include <cutils/properties.h>

#define STE_ENCODER_COLOR_FORMAT "ste.video.enc.fmt"

namespace android {

SurfaceMediaSource::SurfaceMediaSource(uint32_t bufferWidth, uint32_t bufferHeight) :
    mWidth(bufferWidth),
    mHeight(bufferHeight),
    mCurrentSlot(BufferQueue::INVALID_BUFFER_SLOT),
    mCurrentTimestamp(0),
    mFrameRate(30),
    mStopped(false),
    mNumFramesReceived(0),
    mNumFramesEncoded(0),
    mFirstFrameTimestamp(0),
    mIsReading(false)
{
    ALOGV("SurfaceMediaSource::SurfaceMediaSource");

    if (bufferWidth == 0 || bufferHeight == 0) {
        ALOGE("Invalid dimensions %dx%d", bufferWidth, bufferHeight);
    }

    mBufferQueue = new BufferQueue(true, MIN_UNDEQUEUED_BUFFERS);
    mBufferQueue->setDefaultBufferSize(bufferWidth, bufferHeight);
    mBufferQueue->setSynchronousMode(true);
    mBufferQueue->setConsumerUsageBits(GRALLOC_USAGE_HW_VIDEO_ENCODER |
            GRALLOC_USAGE_HW_2D);

    sp<ISurfaceComposer> composer(ComposerService::getComposerService());
    mGraphicBufferAlloc = composer->createGraphicBufferAlloc();
    if (mGraphicBufferAlloc == NULL) {
        ALOGE("createGraphicBufferAlloc() failed in SurfaceMediaSource");
    }

    // Note that we can't create an sp<...>(this) in a ctor that will not keep a
    // reference once the ctor ends, as that would cause the refcount of 'this'
    // dropping to 0 at the end of the ctor.  Since all we need is a wp<...>
    // that's what we create.
    wp<BufferQueue::ConsumerListener> listener;
    sp<BufferQueue::ConsumerListener> proxy;
    listener = static_cast<BufferQueue::ConsumerListener*>(this);
    proxy = new BufferQueue::ProxyConsumerListener(listener);

    status_t err = mBufferQueue->consumerConnect(proxy);
    if (err != NO_ERROR) {
        ALOGE("SurfaceMediaSource: error connecting to BufferQueue: %s (%d)",
                strerror(-err), err);
    }

    for (int i = 0; i < MAX_UNDEQUEUED_BUFFERS; i++) {
        mGraphicBufferYuv[i] = NULL;
    }

    // get video encoder color format property
    char value[PROPERTY_VALUE_MAX];
    property_get(STE_ENCODER_COLOR_FORMAT, &value[0], "");
    ALOGV("%s STE_ENCODER_COLOR_FORMAT = %s ", __func__, value);

    if (strncmp(value, "yuv420mb", 8) == 0) {
        mYuvPixelFormat = PIXEL_FORMAT_YCBCR42XMBN;
    } else if (strncmp(value, "yuv420sp", 8) == 0) {
        mYuvPixelFormat = PIXEL_FORMAT_YCbCr_420_SP;
    } else {
        ALOGE("No Input Color Format Property Using PIXEL_FORMAT_UNKNOWN");
        mYuvPixelFormat = PIXEL_FORMAT_UNKNOWN;
    }

    hw_module_t const* module;
    if (hw_get_module(COPYBIT_HARDWARE_MODULE_ID, &module) == 0) {
        copybit_open(module, &mBlitEngine);
    }
}

SurfaceMediaSource::~SurfaceMediaSource() {
    ALOGV("SurfaceMediaSource::~SurfaceMediaSource");
    if (mBlitEngine != NULL) {
        copybit_close(mBlitEngine);
        mBlitEngine = NULL;
    }
    if (!mStopped) {
        reset();
    }
}

nsecs_t SurfaceMediaSource::getTimestamp() {
    ALOGV("SurfaceMediaSource::getTimestamp");
    Mutex::Autolock lock(mMutex);
    return mCurrentTimestamp;
}

void SurfaceMediaSource::setFrameAvailableListener(
        const sp<FrameAvailableListener>& listener) {
    ALOGV("SurfaceMediaSource::setFrameAvailableListener");
    Mutex::Autolock lock(mMutex);
    mFrameAvailableListener = listener;
}

void SurfaceMediaSource::dump(String8& result) const
{
    char buffer[1024];
    dump(result, "", buffer, 1024);
}

void SurfaceMediaSource::dump(String8& result, const char* prefix,
        char* buffer, size_t SIZE) const
{
    Mutex::Autolock lock(mMutex);

    result.append(buffer);
    mBufferQueue->dump(result);
}

status_t SurfaceMediaSource::setFrameRate(int32_t fps)
{
    Mutex::Autolock lock(mMutex);
    const int MAX_FRAME_RATE = 60;
    if (fps < 0 || fps > MAX_FRAME_RATE) {
        return BAD_VALUE;
    }
    mFrameRate = fps;
    return OK;
}

bool SurfaceMediaSource::isMetaDataStoredInVideoBuffers() const {
    ALOGV("isMetaDataStoredInVideoBuffers");
    return true;
}

int32_t SurfaceMediaSource::getFrameRate( ) const {
    Mutex::Autolock lock(mMutex);
    return mFrameRate;
}

status_t SurfaceMediaSource::start(MetaData *params)
{
    ALOGV("started!");

    mStartTimeNs = 0;
    int64_t startTimeUs;
    if (params && params->findInt64(kKeyTime, &startTimeUs)) {
        mStartTimeNs = startTimeUs * 1000;
    }

    return OK;
}


status_t SurfaceMediaSource::reset()
{
    ALOGV("Reset");

    Mutex::Autolock lock(mMutex);
    // TODO: Add waiting on mFrameCompletedCondition here?
    mStopped = true;

    mFrameAvailableCondition.signal();
    mBufferQueue->consumerDisconnect();

    return OK;
}

sp<MetaData> SurfaceMediaSource::getFormat()
{
    ALOGV("getFormat");

    Mutex::Autolock lock(mMutex);
    sp<MetaData> meta = new MetaData;

    meta->setInt32(kKeyWidth, mWidth);
    meta->setInt32(kKeyHeight, mHeight);
    // The encoder format is set as an opaque colorformat
    // The encoder will later find out the actual colorformat
    // from the GL Frames itself.
    meta->setInt32(kKeyColorFormat, OMX_COLOR_FormatAndroidOpaque);
    meta->setInt32(kKeyStride, mWidth);
    meta->setInt32(kKeySliceHeight, mHeight);
    meta->setInt32(kKeyFrameRate, mFrameRate);
    meta->setCString(kKeyMIMEType, MEDIA_MIMETYPE_VIDEO_RAW);
    return meta;
}

// Pass the data to the MediaBuffer. Pass in only the metadata
// The metadata passed consists of two parts:
// 1. First, there is an integer indicating that it is a GRAlloc
// source (kMetadataBufferTypeGrallocSource)
// 2. This is followed by the buffer_handle_t that is a handle to the
// GRalloc buffer. The encoder needs to interpret this GRalloc handle
// and encode the frames.
// --------------------------------------------------------------
// |  kMetadataBufferTypeGrallocSource | sizeof(buffer_handle_t) |
// --------------------------------------------------------------
// Note: Call only when you have the lock
static void passMetadataBuffer(MediaBuffer **buffer,
        buffer_handle_t bufferHandle) {
    // MediaBuffer allocates and owns this data
    MediaBuffer *tempBuffer = new MediaBuffer(4 + sizeof(buffer_handle_t));
    char *data = (char *)tempBuffer->data();
    if (data == NULL) {
        ALOGE("Cannot allocate memory for metadata buffer!");
        return;
    }
    OMX_U32 type = kMetadataBufferTypeGrallocSource;
    memcpy(data, &type, 4);
    memcpy(data + 4, &bufferHandle, sizeof(buffer_handle_t));
    *buffer = tempBuffer;

    ALOGV("handle = %p, , offset = %d, length = %d",
            bufferHandle, (*buffer)->range_length(), (*buffer)->range_offset());
}

status_t SurfaceMediaSource::read( MediaBuffer **buffer,
                                    const ReadOptions *options)
{
    ALOGV("read");
    Mutex::Autolock lock(mMutex);

    *buffer = NULL;

    // Update the current buffer info
    // TODO: mCurrentSlot can be made a bufferstate since there
    // can be more than one "current" slots.

    BufferQueue::BufferItem item;
    // If the recording has started and the queue is empty, then just
    // wait here till the frames come in from the client side
    while (!mStopped) {

        status_t err = mBufferQueue->acquireBuffer(&item);
        if (err == BufferQueue::NO_BUFFER_AVAILABLE) {
            // wait for a buffer to be queued
            mFrameAvailableCondition.wait(mMutex);
        } else if (err == OK) {

            // First time seeing the buffer?  Added it to the SMS slot
            if (item.mGraphicBuffer != NULL) {
                mBufferSlot[item.mBuf] = item.mGraphicBuffer;
            }

            // check for the timing of this buffer
            if (mNumFramesReceived == 0) {
                mFirstFrameTimestamp = item.mTimestamp;
                // Initial delay
                if (mStartTimeNs > 0) {
                    if (item.mTimestamp < mStartTimeNs) {
                        // This frame predates start of record, discard
                        mBufferQueue->releaseBuffer(item.mBuf, EGL_NO_DISPLAY, EGL_NO_SYNC_KHR);
                        continue;
                    }
                    mStartTimeNs = item.mTimestamp - mStartTimeNs;
                }
            }
            item.mTimestamp = mStartTimeNs + (item.mTimestamp - mFirstFrameTimestamp);

            mNumFramesReceived++;

            break;
        } else {
            ALOGE("read: acquire failed with error code %d", err);
            return ERROR_END_OF_STREAM;
        }

    }

    // If the loop was exited as a result of stopping the recording,
    // it is OK
    if (mStopped) {
        ALOGV("Read: SurfaceMediaSource is stopped. Returning ERROR_END_OF_STREAM.");
        return ERROR_END_OF_STREAM;
    }

    mCurrentSlot = item.mBuf;

    // First time seeing the buffer?  Added it to the SMS slot
    if (item.mGraphicBuffer != NULL) {
        mBufferSlot[mCurrentSlot] = item.mGraphicBuffer;
    }

    // Allocate buffers
    if (mGraphicBufferYuv[mCurrentSlot] == NULL && conversionIsNeeded(mBufferSlot[mCurrentSlot])) {
        ALOGV("Creating new graphicBuffer");

        status_t error;
        sp<GraphicBuffer> graphicBufferYuv(
                mGraphicBufferAlloc->createGraphicBuffer(
                        mWidth, mHeight, mYuvPixelFormat,
                        GRALLOC_USAGE_HW_VIDEO_ENCODER | GRALLOC_USAGE_HW_2D, &error));
        if (graphicBufferYuv == NULL) {
            ALOGE("dequeueBuffer: SurfaceComposer::createGraphicBuffer "
                    "failed");
            return error;
        }

        mGraphicBufferYuv[mCurrentSlot] = graphicBufferYuv;
    }

    int64_t prevTimeStamp = mCurrentTimestamp;

    if (conversionIsNeeded(mBufferSlot[mCurrentSlot]) &&
            OK == convert(mBufferSlot[mCurrentSlot], mGraphicBufferYuv[mCurrentSlot])) {
        mCurrentBuffers.push_back(mGraphicBufferYuv[mCurrentSlot]);
        mCurrentBuffersDQ.push_back(mBufferSlot[mCurrentSlot]);
        mCurrentTimestamp = item.mTimestamp;

        mNumFramesEncoded++;
        // Pass the data to the MediaBuffer. Pass in only the metadata
        passMetadataBuffer(buffer, mGraphicBufferYuv[mCurrentSlot]->handle);
    } else {
        mCurrentBuffers.push_back(mBufferSlot[mCurrentSlot]);
        mCurrentTimestamp = item.mTimestamp;

        mNumFramesEncoded++;
        // Pass the data to the MediaBuffer. Pass in only the metadata
        passMetadataBuffer(buffer, mBufferSlot[mCurrentSlot]->handle);
    }

    (*buffer)->setObserver(this);
    (*buffer)->add_ref();
    (*buffer)->meta_data()->setInt64(kKeyTime, mCurrentTimestamp / 1000);
    ALOGV("Frames encoded = %d, timestamp = %lld, time diff = %lld",
            mNumFramesEncoded, mCurrentTimestamp / 1000,
            mCurrentTimestamp / 1000 - prevTimeStamp / 1000);

    mIsReading = true;

    return OK;
}

bool SurfaceMediaSource::conversionIsNeeded(const sp<GraphicBuffer>& graphicBuffer) {
    // Output format not known so no conversion
    if (mYuvPixelFormat == PIXEL_FORMAT_UNKNOWN) {
        return false;
    }
    return (graphicBuffer->getPixelFormat() != mYuvPixelFormat);
}

static buffer_handle_t getMediaBufferHandle(MediaBuffer *buffer) {
    // need to convert to char* for pointer arithmetic and then
    // copy the byte stream into our handle
    buffer_handle_t bufferHandle;
    memcpy(&bufferHandle, (char*)(buffer->data()) + 4, sizeof(buffer_handle_t));
    return bufferHandle;
}

void SurfaceMediaSource::signalBufferReturned(MediaBuffer *buffer) {
    ALOGV("signalBufferReturned");

    bool foundBuffer = false;

    Mutex::Autolock lock(mMutex);

    buffer_handle_t bufferHandle = getMediaBufferHandle(buffer);
    buffer_handle_t graphicbufferHandle = NULL;

    for (size_t i = 0; i < mCurrentBuffers.size(); i++) {
        if (mCurrentBuffers[i]->handle == bufferHandle) {
            mCurrentBuffers.removeAt(i);
            if (mCurrentBuffersDQ.itemAt(i) != NULL) {
                graphicbufferHandle = mCurrentBuffersDQ.itemAt(i)->handle;
                mCurrentBuffersDQ.removeAt(i);
            }
            foundBuffer = true;
            break;
        }
    }

    if (!foundBuffer) {
        ALOGW("returned buffer was not found in the current buffer list");
    }

    for (int id = 0; id < BufferQueue::NUM_BUFFER_SLOTS; id++) {
        if (mBufferSlot[id] == NULL) {
            continue;
        }

        if (graphicbufferHandle == mBufferSlot[id]->handle || bufferHandle == mBufferSlot[id]->handle) {
            ALOGV("Slot %d returned, matches handle = %p", id,
                    mBufferSlot[id]->handle);

            mBufferQueue->releaseBuffer(id, EGL_NO_DISPLAY, EGL_NO_SYNC_KHR);

            buffer->setObserver(0);
            buffer->release();

            foundBuffer = true;
            break;
        }
    }

    if (!foundBuffer) {
        CHECK(!"signalBufferReturned: bogus buffer");
    }
}

// Part of the BufferQueue::ConsumerListener
void SurfaceMediaSource::onFrameAvailable() {
    ALOGV("onFrameAvailable");

    sp<FrameAvailableListener> listener;
    { // scope for the lock
        Mutex::Autolock lock(mMutex);
        mFrameAvailableCondition.broadcast();
        listener = mFrameAvailableListener;
    }

    if (listener != NULL) {
        ALOGV("actually calling onFrameAvailable");
        listener->onFrameAvailable();
    }
}

// SurfaceMediaSource hijacks this event to assume
// the prodcuer is disconnecting from the BufferQueue
// and that it should stop the recording
void SurfaceMediaSource::onBuffersReleased() {
    ALOGV("onBuffersReleased");

    Mutex::Autolock lock(mMutex);

    mFrameAvailableCondition.signal();
    if (mIsReading) {
        mStopped = true;
    }

    for (int i = 0; i < BufferQueue::NUM_BUFFER_SLOTS; i++) {
       mBufferSlot[i] = 0;
    }
}

// Convert RGBA data received from surface to color format used by encoder
status_t SurfaceMediaSource::convert(const sp<GraphicBuffer> &srcBuf, const sp<GraphicBuffer> &dstBuf) {
    copybit_image_t dstImg;
    dstImg.w = dstBuf->getWidth();
    dstImg.h = dstBuf->getHeight();
    dstImg.format = dstBuf->getPixelFormat();
    dstImg.handle = (native_handle_t*) dstBuf->getNativeBuffer()->handle;

    copybit_image_t srcImg;
    srcImg.w = srcBuf->getWidth();
    srcImg.h = srcBuf->getHeight();
    srcImg.format = srcBuf->getPixelFormat();
    srcImg.base = NULL;
    srcImg.handle = (native_handle_t*) srcBuf->getNativeBuffer()->handle;

    copybit_rect_t dstCrop;
    dstCrop.l = 0;
    dstCrop.t = 0;
    dstCrop.r = dstBuf->getWidth();
    dstCrop.b = dstBuf->getHeight();

    copybit_rect_t srcCrop;
    srcCrop.l = 0;
    srcCrop.t = 0;
    srcCrop.r = srcBuf->getWidth();
    srcCrop.b = srcBuf->getHeight();

    ALOGV("%s dWidth=%d, dHeight=%d, dPixel=%x, sPixel=%x ", __func__, dstImg.w, dstImg.h, dstImg.format, srcImg.format);

    region_iterator clip(Region(Rect(dstCrop.r, dstCrop.b)));
    mBlitEngine->set_parameter(mBlitEngine, COPYBIT_TRANSFORM, 0);

    int err = mBlitEngine->stretch(
            mBlitEngine, &dstImg, &srcImg, &dstCrop, &srcCrop, &clip);
    if (err != 0) {
        ALOGE("\nError: Blit stretch operation failed (err:%d)\n", err);
        if (mBlitEngine) {
            copybit_close(mBlitEngine);
            mBlitEngine = NULL;
        }
        return UNKNOWN_ERROR;
    }

    return OK;
}
} // end of namespace android
