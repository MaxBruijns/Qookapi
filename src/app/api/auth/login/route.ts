import { NextRequest, NextResponse } from "next/server";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { supabaseAdmin } from "../../../../../../lib/supabase";

function jsonError(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}

export async function POST(req: NextRequest) {
  try {
    const { email, password } = await req.json();

    if (!email || !password) {
      return jsonError("Email en wachtwoord zijn verplicht.", 400);
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    // Haal gebruiker op incl hash
    const { data: user, error } = await supabaseAdmin
      .from("users")
      .select("id, email, password_hash, plan, trial_end, first_name, last_name")
      .eq("email", normalizedEmail)
      .maybeSingle();

    if (error) {
      console.error("Supabase login select error:", error);
      return jsonError("Databasefout.", 500);
    }

    if (!user) {
      return jsonError("Onjuiste inloggegevens.", 401);
    }

    // password_hash moet bestaan
    if (!user.password_hash) {
      return jsonError("Account is niet correct ingesteld.", 500);
    }

    const ok = await bcrypt.compare(String(password), String(user.password_hash));
    if (!ok) {
      return jsonError("Onjuiste inloggegevens.", 401);
    }

    const secret = process.env.JWT_SECRET;
    if (!secret) {
      console.error("Missing JWT_SECRET env var");
      return jsonError("Serverconfiguratie ontbreekt.", 500);
    }

    // Token payload (houd dit klein)
    const token = jwt.sign(
      {
        sub: user.id,
        email: user.email,
        plan: user.plan,
      },
      secret,
      { expiresIn: "30d" }
    );

    // Cookie zetten (httpOnly)
    const res = NextResponse.json({
      user: {
        id: user.id,
        email: user.email,
        plan: user.plan,
        trial_end: user.trial_end,
        first_name: user.first_name ?? null,
        last_name: user.last_name ?? null,
      },
      token, // handig voor app; voor web kun je dit later weglaten
    });

    res.cookies.set({
      name: "kooq_session",
      value: token,
      httpOnly: true,
      secure: true, // op Vercel altijd https
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 30, // 30 dagen
    });

    return res;
  } catch (e: any) {
    console.error("Login error:", e);
    return jsonError("Interne serverfout.", 500);
  }
}