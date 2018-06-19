<?php

namespace App\Http\Resources\Admin;

use App\Http\Resources\UserResource;
use Illuminate\Http\Resources\Json\Resource;

class CommentResource extends Resource
{
    /**
     * Transform the resource into an array.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    public function toArray($request)
    {
        return [
            'id'            => $this->id,
            'user'          => new UserResource($this->whenLoaded('user')),
            'parent_id'     => $this->parent_id,
            'reply_user'    => new UserResource($this->whenLoaded('reply_user')),
            'commentable'   => $this->commentable->title,
            'parent_id'     => $this->parent_id,
            'content'       => $this->content,
            'created_at'    => $this->created_at,
        ];
    }
}
