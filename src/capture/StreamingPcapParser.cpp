#include "capture/StreamingPcapParser.h"

#include "base/Binary.h"

#include <stdexcept>

namespace abdc::capture {

void StreamingPcapParser::Append(const std::span<const std::byte> bytes){
    if(bytes.empty())return;if(buffer_.size()-offset_+bytes.size()>32U<<20U)throw std::runtime_error("streaming PCAP buffer bound exceeded");
    if(offset_!=0&&(offset_>1U<<20U||offset_==buffer_.size())){buffer_.erase(buffer_.begin(),buffer_.begin()+static_cast<std::ptrdiff_t>(offset_));offset_=0;}
    buffer_.insert(buffer_.end(),bytes.begin(),bytes.end());
}

std::vector<PcapRecord> StreamingPcapParser::TakeRecords(){std::vector<PcapRecord> out;ParseAvailable(out);return out;}

void StreamingPcapParser::ParseAvailable(std::vector<PcapRecord>& out){
    if(!header_ready_){if(buffer_.size()-offset_<24)return;const auto bytes=std::span<const std::byte>(buffer_).subspan(offset_,24);
        const auto b0=std::to_integer<std::uint8_t>(bytes[0]),b1=std::to_integer<std::uint8_t>(bytes[1]);
        const auto b2=std::to_integer<std::uint8_t>(bytes[2]),b3=std::to_integer<std::uint8_t>(bytes[3]);
        if(b0==0xd4&&b1==0xc3&&b2==0xb2&&b3==0xa1){header_.little_endian=true;header_.resolution=TimestampResolution::Microseconds;}
        else if(b0==0xa1&&b1==0xb2&&b2==0xc3&&b3==0xd4){header_.little_endian=false;header_.resolution=TimestampResolution::Microseconds;}
        else if(b0==0x4d&&b1==0x3c&&b2==0xb2&&b3==0xa1){header_.little_endian=true;header_.resolution=TimestampResolution::Nanoseconds;}
        else if(b0==0xa1&&b1==0xb2&&b2==0x3c&&b3==0x4d){header_.little_endian=false;header_.resolution=TimestampResolution::Nanoseconds;}
        else throw std::runtime_error("unsupported streaming PCAP magic");
        header_.major=binary::ReadU16(bytes,4,header_.little_endian);header_.minor=binary::ReadU16(bytes,6,header_.little_endian);
        header_.snap_length=binary::ReadU32(bytes,16,header_.little_endian);header_.link_type=binary::ReadU32(bytes,20,header_.little_endian);
        if(header_.major!=2||header_.minor!=4||header_.snap_length<27||header_.snap_length>16U<<20U||header_.link_type!=PcapReader::kUsbPcapLinkType)
            throw std::runtime_error("invalid streaming USBPcap global header");offset_+=24;header_ready_=true;}
    while(buffer_.size()-offset_>=16){const auto h=std::span<const std::byte>(buffer_).subspan(offset_,16);
        const auto included=binary::ReadU32(h,8,header_.little_endian),original=binary::ReadU32(h,12,header_.little_endian);
        if(included>header_.snap_length||included>original)throw std::runtime_error("invalid streaming PCAP record lengths");
        if(buffer_.size()-offset_-16<included)return;PcapRecord r;r.sequence=sequence_++;
        r.timestamp_seconds=binary::ReadU32(h,0,header_.little_endian);r.timestamp_fraction=binary::ReadU32(h,4,header_.little_endian);
        r.resolution=header_.resolution;r.original_length=original;
        const auto payload=std::span<const std::byte>(buffer_).subspan(offset_+16,included);r.data.assign(payload.begin(),payload.end());
        (void)r.UnixNanoseconds();out.push_back(std::move(r));offset_+=16+included;}
}

void StreamingPcapParser::Finalize()const{if(!header_ready_)throw std::runtime_error("capture ended before PCAP header");if(buffer_.size()!=offset_)throw std::runtime_error("capture ended with truncated PCAP record");}

const PcapHeader& StreamingPcapParser::Header()const{if(!header_ready_)throw std::logic_error("streaming PCAP header not ready");return header_;}

}  // namespace abdc::capture

