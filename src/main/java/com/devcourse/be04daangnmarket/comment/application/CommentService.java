package com.devcourse.be04daangnmarket.comment.application;

import com.devcourse.be04daangnmarket.comment.dto.CommentDto;
import com.devcourse.be04daangnmarket.image.application.ImageService;
import com.devcourse.be04daangnmarket.image.domain.constant.DomainName;
import com.devcourse.be04daangnmarket.common.image.dto.ImageDto;
import com.devcourse.be04daangnmarket.comment.domain.Comment;
import com.devcourse.be04daangnmarket.comment.repository.CommentRepository;
import com.devcourse.be04daangnmarket.comment.util.CommentConverter;
import com.devcourse.be04daangnmarket.member.application.ProfileService;
import com.devcourse.be04daangnmarket.member.domain.Profile;
import com.devcourse.be04daangnmarket.member.dto.MemberDto;
import com.devcourse.be04daangnmarket.member.dto.ProfileDto;
import com.devcourse.be04daangnmarket.member.util.ProfileConverter;
import com.devcourse.be04daangnmarket.post.application.PostService;
import com.devcourse.be04daangnmarket.post.domain.Post;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.NoSuchElementException;

import static com.devcourse.be04daangnmarket.comment.exception.ErrorMessage.NOT_FOUND_COMMENT;
import static com.devcourse.be04daangnmarket.comment.util.CommentConverter.toResponse;

@Transactional(readOnly = true)
@Service
public class CommentService implements CommentProviderService {
    private static final int START_NUMBER = 0;

    private final ImageService imageService;
    private final CommentRepository commentRepository;
    private final PostService postService;
    private final ProfileService profileService;

    public CommentService(ImageService imageService,
                          CommentRepository commentRepository,
                          PostService postService,
                          ProfileService profileService) {
        this.imageService = imageService;
        this.commentRepository = commentRepository;
        this.postService = postService;
        this.profileService = profileService;
    }

    @Transactional
    public CommentDto.CommentResponse create(Long postId,
                                             Long userId,
                                             String username,
                                             String content,
                                             List<ImageDto.ImageDetail> files) {
        Member member = memberService.getMember(userId);
        Post post = postService.findPostById(postId);
        Comment comment = CommentConverter.toEntity(content, member, post);
        comment.addPost(post);

        createCommentGroupNumber(comment);

        Comment saved = commentRepository.save(comment);
        List<String> imagePaths = imageService.save(files, DomainName.COMMENT, saved.getId());

        return toResponse(saved, imagePaths, username);
    }

    private void createCommentGroupNumber(Comment comment) {
        Integer groupNumber = commentRepository.findMaxCommentGroup().orElse(START_NUMBER);
        comment.addGroup(groupNumber);
    }

    @Transactional
    public CommentDto.CommentResponse createReply(Long postId,
                                                  Long userId,
                                                  String username,
                                                  int commentGroup,
                                                  String content,
                                                  List<ImageDto.ImageDetail> files) {
        Member member = memberService.getMember(userId);
        Post post = postService.findPostById(postId);
        Comment comment = CommentConverter.toEntity(post, content, commentGroup, member);
        comment.addPost(post);

        addMaxSequenceToReplyComment(commentGroup, comment);

        Comment saved = commentRepository.save(comment);
        List<String> imagePaths = imageService.save(files, DomainName.COMMENT, saved.getId());

        return toResponse(saved, imagePaths, username);
    }

    private void addMaxSequenceToReplyComment(int commentGroup, Comment comment) {
        Integer seqNumber = commentRepository.findMaxSeqFromCommentGroup(commentGroup)
                .orElseThrow(() -> new NoSuchElementException(NOT_FOUND_COMMENT.getMessage()));
        comment.addSeq(seqNumber);
    }

    @Transactional
    public void delete(Long id) {
        Comment comment = getComment(id);

        if (comment.isGroupComment()) {
            List<Comment> sameGroupComments = commentRepository.findAllByCommentGroup(comment.getCommentGroup());

            for (Comment sameGroupComment : sameGroupComments) {
                deleteComment(sameGroupComment);
            }
        }

        deleteComment(comment);
    }

    @Override
    public Comment getComment(Long id) {
        return commentRepository.findById(id)
                .orElseThrow(() -> new NoSuchElementException(NOT_FOUND_COMMENT.getMessage()));
    }

    private void deleteComment(Comment comment) {
        comment.deleteStatus();
        imageService.deleteAllImages(DomainName.COMMENT, comment.getId());
    }

    public CommentDto.CommentResponse getDetail(Long id) {
        Comment comment = getComment(id);

        String username = profileService.getOne(comment.getMemberId()).getUsername();
        List<String> imagePaths = imageService.getImages(DomainName.COMMENT, id);

        return toResponse(comment, imagePaths, username);
    }

    @Override
    public Page<CommentDto.PostCommentResponse> getPostComments(Long postId, Pageable pageable) {
        List<Comment> postComments = commentRepository.findAllByPostIdToSeqIsZero(postId);

        List<CommentDto.PostCommentResponse> postCommentResponses = postComments.stream()
                .map(comment -> {
                    String commentUsername = profileService.getOne(comment.getMemberId()).getUsername();
                    String postTitle = postService.findPostById(comment.getPostId()).getTitle();
                    List<String> imagePaths = imageService.getImages(DomainName.COMMENT, comment.getId());
                    List<CommentDto.CommentResponse> replyCommentResponses = getReplyComments(comment);

                    return toResponse(comment, commentUsername, postTitle, imagePaths, replyCommentResponses);
                })
                .toList();

        return new PageImpl<>(postCommentResponses, pageable, postCommentResponses.size());
    }

    private List<CommentDto.CommentResponse> getReplyComments(Comment comment) {
        List<Comment> replyComments = commentRepository.findRepliesByCommentGroup(comment.getCommentGroup());
      
        return replyComments.stream()
                .map(reply -> {
                    String replyUsername = profileService.getOne(reply.getMemberId()).getUsername();
                    List<String> imagePaths = imageService.getImages(DomainName.COMMENT, reply.getId());

                    return toResponse(reply, imagePaths, replyUsername);
                })
                .toList();
    }

    @Transactional
    public CommentDto.CommentResponse update(Long id,
                                             Long postId,
                                             String username,
                                             String content,
                                             List<ImageDto.ImageDetail> files) {
        Comment comment = getComment(id);
        comment.update(content);

        imageService.deleteAllImages(DomainName.COMMENT, id);
        List<String> imagePaths = imageService.save(files, DomainName.COMMENT, id);

        return toResponse(comment, imagePaths, username);
    }

    public Page<ProfileDto.Response> getCommenterByPostId(Long postId, Long writerId, Pageable pageable) {
         return commentRepository.findDistinctMembersByPostIdAndNotInWriterId(postId, writerId, pageable)
                .map(member -> {
                    Profile memberProfile = profileService.getOne(member.getId());

                    return ProfileConverter.toResponse(memberProfile);
                });
    }
}
