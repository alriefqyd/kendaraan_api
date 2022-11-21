<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class KendaraanController extends Controller
{
    public function index(){
        return response()->json(User::all());
    }
}
