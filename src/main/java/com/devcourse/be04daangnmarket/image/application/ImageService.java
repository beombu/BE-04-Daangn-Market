package com.devcourse.be04daangnmarket.image.application;

import com.devcourse.be04daangnmarket.image.domain.DomainName;
import com.devcourse.be04daangnmarket.image.domain.File;
import com.devcourse.be04daangnmarket.image.dto.ImageResponse;
import com.devcourse.be04daangnmarket.image.exception.FileDeleteException;
import com.devcourse.be04daangnmarket.image.exception.FileUploadException;
import com.devcourse.be04daangnmarket.image.repository.ImageRepository;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.devcourse.be04daangnmarket.image.exception.ExceptionMessage.FILE_DELETE_EXCEPTION;
import static com.devcourse.be04daangnmarket.image.exception.ExceptionMessage.FILE_UPLOAD_EXCEPTION;

@Transactional(readOnly = true)
@Service
public class ImageService {

	@Value("${custom.base-path.image}")
	private String FOLDER_PATH;

	private final String RELATIVE_PATH = "images/";

	private final ImageRepository imageRepository;

	public ImageService(ImageRepository imageRepository) {
		this.imageRepository = imageRepository;
	}

	@Transactional
	public List<ImageResponse> uploadImages(List<MultipartFile> multipartFiles, DomainName domainName, Long domainId) {
		List<ImageResponse> responses = new ArrayList<>();

		if (isExistImages(multipartFiles)) {
			for (MultipartFile multipartFile : multipartFiles) {
				if(multipartFile.isEmpty()) continue;

				String originalName = multipartFile.getOriginalFilename();
				String uniqueName = createUniqueName(originalName);

				saveImageToLocalStorage(multipartFile, uniqueName);

				File file = new File(multipartFile.getOriginalFilename(), multipartFile.getContentType(),
					multipartFile.getSize(), getRelativePath(uniqueName), domainName, domainId);
				imageRepository.save(file);
				responses.add(toDto(file));
			}
		}

		return responses;
	}

	private boolean isExistImages(List<MultipartFile> multipartFiles) {
		return !multipartFiles.isEmpty();
	}

	private String createUniqueName(String originalName) {
		return UUID.randomUUID() + "-" + StringUtils.cleanPath(originalName);

	}

	private void saveImageToLocalStorage(MultipartFile multipartFile, String uniqueName) {
		try {
			java.io.File file = new java.io.File(FOLDER_PATH + RELATIVE_PATH);

			if (isExistFile(file)) {
				file.mkdirs();
			}
			multipartFile.transferTo(new java.io.File(getFullPath(uniqueName)));
		} catch (IOException e) {
			throw new FileUploadException(FILE_UPLOAD_EXCEPTION.getMessage());
		}
	}

	private static boolean isExistFile(java.io.File file) {
		return !file.exists();
	}

	private String getRelativePath(String uniqueName) {
		return RELATIVE_PATH + uniqueName;
	}

	private String getFullPath(String uniqueName) {
		return FOLDER_PATH + RELATIVE_PATH + uniqueName;
	}

	public List<ImageResponse> getImages(DomainName domainName, Long domainId) {
		List<File> files = imageRepository.findAllByDomainNameAndDomainId(domainName, domainId);

		return files.stream()
			.map(this::toDto)
			.collect(Collectors.toList());
	}

	private ImageResponse toDto(File file) {
		return new ImageResponse(
			file.getName(),
			file.getPath(),
			file.getType(),
			file.getSize(),
			file.getDomainName(),
			file.getDomainId());
	}

	@Transactional
	public void deleteAllImages(DomainName domainName, Long domainId) {
		List<File> entities = getAllImageEntities(domainName, domainId);

		if (entities.isEmpty()) {
			return;
		}

		entities.stream()
			.map(File::getPath)
			.forEach(this::deleteImageToLocalStorage);

		imageRepository.deleteAllByDomainNameAndDomainId(domainName, domainId);
	}

	private List<File> getAllImageEntities(DomainName domainName, Long domainId) {
		return imageRepository.findAllByDomainNameAndDomainId(domainName, domainId);
	}

	private void deleteImageToLocalStorage(String path) {
		Path fullPath = Paths.get(FOLDER_PATH + path);

		try {
			Files.delete(fullPath);
		} catch (IOException e) {
			throw new FileDeleteException(FILE_DELETE_EXCEPTION.getMessage());
		}
	}
}
