import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db/client";
import { getBaseUrl } from "@/lib/env";
import { canConnectInstagramAccount } from "@/lib/instagram-accounts";
import { getLongLivedToken, getUnifiedInstagramAccount, getUserInfo, subscribeInstagramAccountToWebhooks } from "@/lib/meta/client";
import {
  encryptToken,
  exchangeCodeForToken,
  exchangeUnifiedCode,
  verifyOAuthState,
} from "@/lib/meta/oauth";
import { canManageWorkspace } from "@/lib/workspace-access";

export async function GET(request: NextRequest) {
  const code = request.nextUrl.searchParams.get("code");
  const error = request.nextUrl.searchParams.get("error");
  const state = verifyOAuthState(request.nextUrl.searchParams.get("state"));
  const baseUrl = getBaseUrl();

  if (error) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=denied`);
  }

  if (!code || !state) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=invalid`);
  }

  const session = await auth();
  if (!session?.user?.id) {
    return NextResponse.redirect(`${baseUrl}/login`);
  }

  const membership = await prisma.workspaceMember.findFirst({
    where: {
      workspaceId: state.workspaceId,
      userId: session.user.id,
    },
  });

  if (!membership || !canManageWorkspace(membership.role)) {
    return NextResponse.redirect(`${baseUrl}/settings?instagram=forbidden`);
  }

  try {
    const redirectUri = `${baseUrl}/api/instagram/callback`;
    const account = process.env.INSTAGRAM_UNIFIED_CONFIG_ID
      ? await connectUnifiedAccount(code, redirectUri)
      : await connectLegacyAccount(code, redirectUri);
    const { accessToken: longLivedToken, profile: userInfo, expiresAt: tokenExpiresAt } = account;
    // Webhooks and the messaging API key off the professional account ID
    // (user_id), not the app-scoped `id`. Store user_id so comment webhooks
    // can be matched back to this account. Fall back to id if user_id is
    // ever absent.
    const instagramId = userInfo.user_id ?? userInfo.id;
    const connection = await canConnectInstagramAccount({
      workspaceId: state.workspaceId,
      instagramId,
    });

    if (!connection.allowed) {
      return NextResponse.redirect(
        `${baseUrl}/settings?instagram=already_connected`
      );
    }

    const encryptedToken = encryptToken(longLivedToken);

    let webhookSubscribed = false;
    try {
      const subscription = await subscribeInstagramAccountToWebhooks(
        instagramId,
        longLivedToken
      );
      webhookSubscribed = Boolean(subscription.success);
    } catch (subscriptionError) {
      console.warn(
        "[Instagram Callback] Webhook subscription failed:",
        subscriptionError
      );
    }

    const data = {
      username: userInfo.username,
      name: userInfo.name,
      accessToken: encryptedToken,
      tokenExpiresAt,
      webhookSubscribed,
    };
    const existing = await prisma.instagramAccount.findUnique({ where: { instagramId } });
    if (existing) {
      const updated = await prisma.instagramAccount.updateMany({
        where: { id: existing.id, workspaceId: state.workspaceId, provider: 'META' }, data,
      });
      if (!updated.count) return NextResponse.redirect(`${baseUrl}/settings?instagram=already_connected`);
    } else {
      await prisma.instagramAccount.create({ data: { ...data, workspaceId: state.workspaceId, instagramId, provider: 'META' } });
    }

    return NextResponse.redirect(`${baseUrl}/dashboard?connected=true`);
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    console.error("[Instagram Callback] Error:", err);
    // The message is the only diagnostic a self-hoster gets for a failed
    // connect, so persist it alongside the other operational events rather
    // than leaving it in server logs they may not be able to reach.
    await prisma.operationalEvent
      .create({
        data: {
          source: "SYSTEM",
          level: "ERROR",
          workspaceId: state.workspaceId,
          message: "Instagram connection failed",
          payload: { reason: message },
        },
      })
      .catch(() => {});

    return NextResponse.redirect(
      `${baseUrl}/settings?instagram=failed&reason=${encodeURIComponent(
        message.slice(0, 200)
      )}`
    );
  }
}

async function connectUnifiedAccount(code: string, redirectUri: string) {
  const accessToken = await exchangeUnifiedCode(code, redirectUri);
  return { accessToken, ...await getUnifiedInstagramAccount(accessToken) };
}

async function connectLegacyAccount(code: string, redirectUri: string) {
  const short = await exchangeCodeForToken(code, redirectUri);
  const token = await getLongLivedToken(short.accessToken);
  return {
    accessToken: token.accessToken,
    profile: await getUserInfo(token.accessToken),
    expiresAt: new Date(Date.now() + token.expiresIn * 1000),
  };
}
