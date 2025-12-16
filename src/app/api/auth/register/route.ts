import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { supabaseAdmin } from '../../../../../lib/supabase';

export async function POST(req: NextRequest) {
  try {
    const { firstName, lastName, email, password } = await req.json();

    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email en wachtwoord zijn verplicht.' },
        { status: 400 }
      );
    }

    const normalizedEmail = String(email).trim().toLowerCase();

    // Check of gebruiker al bestaat
    const { data: existing, error: existingErr } = await supabaseAdmin
      .from('users')
      .select('id')
      .eq('email', normalizedEmail)
      .maybeSingle();

    if (existingErr) {
      console.error(existingErr);
      return NextResponse.json({ error: 'Databasefout.' }, { status: 500 });
    }

    if (existing) {
      return NextResponse.json(
        { error: 'E-mailadres bestaat al.' },
        { status: 409 }
      );
    }

    const password_hash = await bcrypt.hash(String(password), 10);

    const now = new Date();
    const trialEnd = new Date(now.getTime() + 14 * 24 * 60 * 60 * 1000);

    const { data: user, error } = await supabaseAdmin
      .from('users')
      .insert([
        {
          email: normalizedEmail,
          password_hash,
          first_name: firstName ?? null,
          last_name: lastName ?? null,
          plan: 'trial',
          trial_start: now.toISOString(),
          trial_end: trialEnd.toISOString(),
        },
      ])
      .select('id, email, plan, trial_end')
      .single();

    if (error) {
      console.error(error);
      return NextResponse.json(
        { error: 'Registratie mislukt.' },
        { status: 500 }
      );
    }

    const res = NextResponse.json({ user }, { status: 201 });

    // eenvoudige sessie-cookie
    res.cookies.set('qook_session', user.id, {
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
      maxAge: 60 * 60 * 24 * 14,
    });

    return res;
  } catch (err) {
    console.error(err);
    return NextResponse.json(
      { error: 'Onverwachte fout.' },
      { status: 500 }
    );
  }
}
