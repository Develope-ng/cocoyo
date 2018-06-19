<?php

namespace App\Http\Controllers\Admin;

use App\Http\Resources\Admin\CommentResource;
use App\Models\Comment;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;

class CommentController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @param Request $request
     * @return \Illuminate\Http\Resources\Json\AnonymousResourceCollection
     */
    public function index(Request $request)
    {
        $parent_id = $request->input('parent_id', 0);
        $comments = Comment::latest()->where('parent_id', $parent_id)->paginate(10);

        $comments->load(['user', 'reply_user', 'commentable']);

        return CommentResource::collection($comments);
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param Comment $comment
     * @return CommentResource
     */
    public function edit(Comment $comment)
    {
        $comment->load('user');

        return new CommentResource($comment);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param Comment $comment
     * @param  \Illuminate\Http\Request $request
     * @return \Response
     */
    public function update(Comment $comment, Request $request)
    {
        $comment->fill(['content' => $request->input('content')]);

        $comment->save();

        return $this->noContent();
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param Comment $comment
     * @return \Response
     * @throws \Exception
     */
    public function destroy(Comment $comment)
    {
        $this->recursive($comment);

        return $this->noContent();
    }

    /**
     * 递归删除评论
     *
     * @param Comment $comment
     * @return bool
     * @throws \Exception
     */
    protected function recursive(Comment $comment)
    {
        $comment->delete();

        $child_comment = Comment::where('parent_id', $comment->id)->first();

        if (! $child_comment) {
            return true;
        }

        $child_comment->delete();

        return $this->recursive($child_comment);
    }
}
