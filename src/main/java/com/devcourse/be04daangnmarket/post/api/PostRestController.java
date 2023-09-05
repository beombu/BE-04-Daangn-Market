package com.devcourse.be04daangnmarket.post.api;

import java.io.IOException;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.devcourse.be04daangnmarket.common.auth.User;
import com.devcourse.be04daangnmarket.post.application.PostService;
import com.devcourse.be04daangnmarket.post.domain.Category;
import com.devcourse.be04daangnmarket.post.domain.Status;
import com.devcourse.be04daangnmarket.post.dto.PostDto;

@RestController
@RequestMapping("api/v1/posts")
public class PostRestController {

	private final PostService postService;

	public PostRestController(PostService postService) {
		this.postService = postService;
	}

	@PostMapping
	public ResponseEntity<PostDto.Response> createPost(PostDto.CreateRequest request,
		@AuthenticationPrincipal User user) throws IOException {
		PostDto.Response response = postService.create(user.getId(), request.title(), request.description()
			, request.price(), request.transactionType(), request.category(), request.receivedImages());

		return new ResponseEntity<>(response, HttpStatus.CREATED);
	}

	@GetMapping("/{id}")
	public ResponseEntity<PostDto.Response> getPost(@PathVariable Long id) {
		PostDto.Response response = postService.getPost(id);

		return new ResponseEntity<>(response, HttpStatus.OK);
	}

	@GetMapping
	public ResponseEntity<Page<PostDto.Response>> getAllPost(@RequestParam(defaultValue = "0") int page,
		@RequestParam(defaultValue = "10") int size) {
		Pageable pageable = PageRequest.of(page, size);
		Page<PostDto.Response> responses = postService.getAllPost(pageable);

		return new ResponseEntity<>(responses, HttpStatus.OK);
	}

	@GetMapping("/category")
	public ResponseEntity<Page<PostDto.Response>> getPostByCategory(@RequestParam Category category,
		@RequestParam(defaultValue = "0") int page,
		@RequestParam(defaultValue = "10") int size) {
		Pageable pageable = PageRequest.of(page, size);
		Page<PostDto.Response> response = postService.getPostByCategory(category, pageable);

		return new ResponseEntity<>(response, HttpStatus.OK);
	}

	@GetMapping("/member/{memberId}")
	public ResponseEntity<Page<PostDto.Response>> getPostByCategory(@PathVariable Long memberId,
		@RequestParam(defaultValue = "0") int page,
		@RequestParam(defaultValue = "10") int size) {
		Pageable pageable = PageRequest.of(page, size);
		Page<PostDto.Response> response = postService.getPostByMemberId(memberId, pageable);

		return new ResponseEntity<>(response, HttpStatus.OK);
	}

	@PutMapping("/{id}")
	public ResponseEntity<PostDto.Response> updatePost(@PathVariable Long id, PostDto.UpdateRequest request) {
		PostDto.Response response = postService.update(id, request.title(), request.description()
			, request.price(), request.transactionType(), request.category(), request.receivedImages());

		return new ResponseEntity<>(response, HttpStatus.OK);
	}

	@PatchMapping("/{id}/status")
	public ResponseEntity<PostDto.Response> updatePostStatus(@PathVariable Long id,
		PostDto.StatusUpdateRequest request) {
		PostDto.Response response = postService.updateStatus(id, request.status());

		return new ResponseEntity<>(response, HttpStatus.OK);
	}

	@DeleteMapping("/{id}")
	public ResponseEntity<Void> deletePost(@PathVariable Long id) {
		postService.delete(id);

		return ResponseEntity.noContent().build();
	}

}
