package com.devcourse.be04daangnmarket.image.dto;

import com.devcourse.be04daangnmarket.image.domain.constant.DomainName;

public class ImageDto {
    public record ImageResponse(
            String name,
            String path,
            String type,
            long size,
            DomainName domainName,
            Long domainId
    ) {
    }
}
