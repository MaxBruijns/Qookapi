import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { supabaseAdmin } from "@/lib/supabase";

function jsonError(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => null);

    const email = body?.email;
    const password = body?.password;

    if (!email || !password) {
      return jsonError("Email en wachtwoord zijn verplicht.", 400);
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    const { data: user, error } = await supabaseAdmin
      .from("users")
      .select("id,email,password_hash,plan,trial_end,first_name,last_name")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (error) {
      console.error("Login select error:", error);
      return jsonError("Databasefout.", 500);
    }

    if (!user || !user.password_hash) {
      return jsonError("Onjuiste inloggegevens.", 401);
    }

    const ok = await bcrypt.compare(String(password), String(user.password_hash));
    if (!ok) {
      return jsonError("Onjuiste inloggegevens.", 401);
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      console.error("Missing JWT_SECRET");
      return jsonError("Serverconfiguratie ontbreekt.", 500);
    }

    const token = jwt.sign(
      { sub: user.id, email: user.email, plan: user.plan ?? "free" },
      secret,
      { expiresIn: "30d" }
    );

    const res = NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan ?? "free",
        trial_end: user.trial_end ?? null,
        first_name: user.first_name ?? null,
        last_name: user.last_name ?? null,
      },
      token,
    });

    // Cookie (veilig voor web). Voor apps kun je token gebruiken.
    res.cookies.set({
      name: "kooq_session",
      value: token,
      httpOnly: true,
      secure: true, // Vercel is https
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 30, // 30 dagen
    });

    return res;
  } catch (e) {
    console.error("Login error:", e);
    return jsonError("Interne serverfout.", 500);
  }
}
