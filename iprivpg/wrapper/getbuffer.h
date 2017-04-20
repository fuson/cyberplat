#ifndef GETBUFFER_H
#define GETBUFFER_H

#include <node_version.h>

#ifdef NODE_MINOR_VERSION
#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION == 10
#include <node.h>
#include <node_buffer.h>
#endif
#endif

//---------------------------------------------------------------------------------------
class GetBuffer
{
	const v8::Local<v8::Value> & mValue;
	char * mBuffer;
	int mLength;

	v8::String::Utf8Value * mStringValue;

public:
	//---------------------------------------------------------------------------------------
	explicit GetBuffer(const v8::Local<v8::Value> & aValue) :
		mValue(aValue), mBuffer(0), mLength(0), mStringValue(0)
	{
        //printf("NODE v%d.%d\n\n", NODE_MAJOR_VERSION, NODE_MINOR_VERSION);
        
	    std::string inType = *v8::String::Utf8Value(aValue->ToObject()->ObjectProtoToString());

        // node::Buffer * b = node::ObjectWrap::Unwrap<node::Buffer>(aValue);

	    //printf("in object type: %s\n b=%d\n", inType.c_str(), b);

#if V8_MAJOR_VERSION > 0 || V8_MINOR_VERSION > 10
		if (aValue->IsUint8Array())
		{
			v8::Uint8Array * in = v8::Uint8Array::Cast(*aValue);

		    if (in->HasBuffer())
			{
		    	mBuffer = (char *)in->Buffer()->GetContents().Data() + in->ByteOffset();
		    	mLength = in->ByteLength();
			}
            
            return;
		}
#endif            

#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION == 10
        if (aValue->IsObject())
        {
            mBuffer = node::Buffer::Data(aValue->ToObject());
            mLength = node::Buffer::Length(aValue->ToObject());
            
            return;
        }        
#endif            
        if (aValue->IsString())
		{
			mStringValue = new v8::String::Utf8Value(aValue);
			mBuffer = **mStringValue;
			mLength = mStringValue->length();
            
            return;
		}
	}

	//---------------------------------------------------------------------------------------
	virtual ~GetBuffer()
	{
		if (mStringValue)
		{
			delete mStringValue;
			mStringValue = 0;
		}
	}

	//---------------------------------------------------------------------------------------
	bool isValid() const
	{
		return mBuffer && mLength > 0;
	}

	//---------------------------------------------------------------------------------------
	char * getPtr() const
	{
		return mBuffer;
	}

	//---------------------------------------------------------------------------------------
	int getLength() const
	{
		return mLength;
	}
};


#endif
//---------------------------------------------------------------------------------------
