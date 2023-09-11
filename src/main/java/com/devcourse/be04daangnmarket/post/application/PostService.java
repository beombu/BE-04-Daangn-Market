package com.devcourse.be04daangnmarket.post.application;

import static com.devcourse.be04daangnmarket.post.exception.ErrorMessage.*;

import java.io.IOException;
import java.util.List;

import com.devcourse.be04daangnmarket.image.dto.ImageDto;
import com.devcourse.be04daangnmarket.post.exception.NotFoundPostException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import com.devcourse.be04daangnmarket.image.application.ImageService;
import com.devcourse.be04daangnmarket.image.domain.constant.DomainName;
import com.devcourse.be04daangnmarket.member.application.MemberService;
import com.devcourse.be04daangnmarket.member.dto.MemberDto;
import com.devcourse.be04daangnmarket.post.domain.constant.Category;
import com.devcourse.be04daangnmarket.post.domain.Post;
import com.devcourse.be04daangnmarket.post.domain.constant.Status;
import com.devcourse.be04daangnmarket.post.domain.constant.TransactionType;
import com.devcourse.be04daangnmarket.post.dto.PostDto;
import com.devcourse.be04daangnmarket.post.repository.PostRepository;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Service
@Transactional(readOnly = true)
public class PostService {
	private final PostRepository postRepository;
	private final ImageService imageService;
	private final MemberService memberService;

	public PostService(PostRepository postRepository, ImageService imageService, MemberService memberService) {
		this.postRepository = postRepository;
		this.imageService = imageService;
		this.memberService = memberService;
	}

	@Transactional
	public PostDto.Response create(Long memberId,
								   String title,
								   String description,
								   int price,
								   TransactionType transactionType,
								   Category category,
								   List<MultipartFile> files) throws IOException {
		Post post = new Post(
			memberId,
			title,
			description,
			price,
			transactionType,
			category
		);

		postRepository.save(post);

		List<ImageDto.ImageResponse> images = imageService.uploadImages(files, DomainName.POST, post.getId());

		return toResponse(post, images);
	}

	@Transactional
	public PostDto.Response getPost(Long id, HttpServletRequest req, HttpServletResponse res) {
		Post post = findPostById(id);

		if (!isViewed(id, req, res))
			post.updateView();

		List<ImageDto.ImageResponse> images = imageService.getImages(DomainName.POST, id);

		return toResponse(post, images);
	}

	public Page<PostDto.Response> getAllPost(Pageable pageable) {
		return postRepository.findAll(pageable).map(post -> {
			List<ImageDto.ImageResponse> images = imageService.getImages(DomainName.POST, post.getId());

			return toResponse(post, images);
		});
	}

	public Page<PostDto.Response> getPostByCategory(Category category, Pageable pageable) {
		return postRepository.findByCategory(category, pageable).map(post -> {
			List<ImageDto.ImageResponse> images = imageService.getImages(DomainName.POST, post.getId());

			return toResponse(post, images);
		});
	}

	public Page<PostDto.Response> getPostByMemberId(Long memberId, Pageable pageable) {
		return postRepository.findByMemberId(memberId, pageable).map(post -> {
			List<ImageDto.ImageResponse> images = imageService.getImages(DomainName.POST, post.getId());

			return toResponse(post, images);
		});
	}

	public Page<PostDto.Response> getPostByKeyword(String keyword, Pageable pageable) {
		return postRepository.findByTitleContaining(keyword, pageable).map(post -> {
			List<ImageDto.ImageResponse> images = imageService.getImages(DomainName.POST, post.getId());

			return toResponse(post, images);
		});
	}

	public Page<PostDto.Response> getPostByBuyerId(Long buyerId, Pageable pageable) {
		return postRepository.findByBuyerId(buyerId, pageable).map(post -> {
			List<ImageDto.ImageResponse> images = imageService.getImages(DomainName.POST, post.getId());

			return toResponse(post, images);
		});
	}

	@Transactional
	public PostDto.Response update(Long id, String title, String description, int price,
		TransactionType transactionType, Category category, List<MultipartFile> files) {
		Post post = findPostById(id);

		post.update(title, description, price, transactionType, category);
		imageService.deleteAllImages(DomainName.POST, id);

		List<ImageDto.ImageResponse> images = imageService.uploadImages(files, DomainName.POST, id);

		return toResponse(post, images);
	}

	@Transactional
	public PostDto.Response updateStatus(Long id, Status status) {
		Post post = findPostById(id);
		post.updateStatus(status);

		List<ImageDto.ImageResponse> images = imageService.getImages(DomainName.POST, post.getId());

		return toResponse(post, images);
	}

	public Post findPostById(Long id) {
		return postRepository.findById(id)
			.orElseThrow(() -> new NotFoundPostException(NOT_FOUND_POST.getMessage()));
	}

	@Transactional
	public void delete(Long id) {
		postRepository.deleteById(id);
		imageService.deleteAllImages(DomainName.POST, id);
	}

	@Transactional
	public PostDto.Response purchaseProduct(Long id, Long buyerId) {
		Post post = findPostById(id);
		post.purchased(buyerId);

		List<ImageDto.ImageResponse> images = imageService.getImages(DomainName.POST, post.getId());

		return toResponse(post, images);
	}

	private PostDto.Response toResponse(Post post, List<ImageDto.ImageResponse> images) {
		MemberDto.Response member = memberService.getProfile(post.getMemberId());

		return new PostDto.Response(
			post.getId(),
			post.getMemberId(),
			member.username(),
			post.getTitle(),
			post.getDescription(),
			post.getPrice(),
			post.getViews(),
			post.getTransactionType().getDescription(),
			post.getCategory().getDescription(),
			post.getStatus().getDescription(),
			images,
			post.getBuyerId(),
			post.getCreatedAt()
		);
	}

	private boolean isViewed(Long id, HttpServletRequest req, HttpServletResponse res) {
		String cookieName = Long.toString(id);
		String cookieValue = Long.toString(id);
		Cookie[] cookies = req.getCookies();

		if (cookies == null) {
			return false;
		}

		for (Cookie cookie : cookies) {
			if (cookie.getName().contains(cookieName)) {
				return true;
			}
		}

		Cookie cookie = new Cookie(cookieName, cookieValue);
		cookie.setPath("/");
		cookie.setMaxAge(60);
		res.addCookie(cookie);

		return false;
	}
}
