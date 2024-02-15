<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Illuminate\Support\Facades\Auth;

class UserController extends Controller
{
    public function register(Request $request)
    {

        $fields = $request->validate([
            'name' => 'required|max:20',
            'email' => 'required|string|unique:users,email',
            'password' => ['required', 'string'],
        ]);

        // Create a new user
        $user = User::create([
            'name' => $fields['name'],
            'email' => $fields['email'],
            'password' => Hash::make($fields['password']),
        ]);

        // Create and return an access token for the new user
        $token = $user->createToken('usertoken')->plainTextToken;

        return response()->json(['token' => $token, 'user' => $user]);
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        // Attempt to authenticate the user
        if (Auth::attempt($credentials)) {
            $user = Auth::user();

            // Create and return an access token for the authenticated user
            $token = $user->createToken('usertoken')->plainTextToken;

            return response()->json(['token' => $token, 'user' => $user]);
        }

        // Authentication failed
        return response()->json(['message' => 'Invalid credentials'], 401);
    }

    public function logout(Request $request)
    {
        
        // Revoke all tokens for the authenticated user
        auth()->user()->tokens()->delete();

        return response()->json(['message' => 'Successfully logged out']);
    }
}
