<?php

namespace App\Http\Requests;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Validation\Rule;

class ArticleRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * @return bool
     */
    public function authorize()
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array
     */
    public function rules()
    {
        return [
            'category_id' => [
                'required',
                Rule::exists('categories', 'id')
            ],
            'title' => 'required|min:3|max:255',
            'page_image' => 'required',
            'content' => 'required',
            'meta_description' => 'required',
            'published_at' => 'required',
            'tags' => 'required'
        ];
    }
}
