<?php

namespace App\Http\Controllers\Admin;

use App\Http\Resources\LinkResource;
use App\Models\Link;
use App\Services\FileManager\BaseManager;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Cache;

class LinkController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        return LinkResource::collection(Link::latest()->paginate(10));
    }


    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Response
     */
    public function store(Request $request)
    {
        $this->validate($request, [
            'name' => 'required|min:1|max:255',
            'link' => 'required|min:1|max:255',
            'image' => 'required'
        ]);

        Link::create($request->all());

        // 清楚缓存
        Cache::forget('cocoyo_links');

        return $this->noContent();
    }

    /**
     * modify resource status
     *
     * @param Link $link
     * @return \Response
     */
    public function status(Link $link)
    {
        $link->status = ! $link->status;

        $link->save();

        return $this->noContent();
    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param Link $link
     * @return LinkResource
     */
    public function edit(Link $link)
    {
        return new LinkResource($link);
    }

    /**
     * Update the specified resource in storage.
     *
     * @param Link $link
     * @param  \Illuminate\Http\Request $request
     * @return \Response
     */
    public function update(Link $link, Request $request)
    {
        $this->validate($request, [
            'name' => 'required|min:1|max:255',
            'link' => 'required|min:1|max:255',
            'image' => 'required'
        ]);

       $link->fill($request->all());

       $link->save();

        // 清楚缓存
        Cache::forget('cocoyo_links');

        return $this->noContent();
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param Link $link
     * @return \Response
     * @throws \Exception
     */
    public function destroy(Link $link)
    {
       $link->delete();

        // 清楚缓存
        Cache::forget('cocoyo_links');

        return $this->noContent();
    }
}
