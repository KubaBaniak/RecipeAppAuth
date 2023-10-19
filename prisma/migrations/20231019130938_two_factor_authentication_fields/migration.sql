-- CreateTable
CREATE TABLE "TwoFactorAuth" (
    "userId" INTEGER NOT NULL,
    "secretKey" TEXT NOT NULL,
    "isEnabled" BOOLEAN NOT NULL DEFAULT false
);

-- CreateTable
CREATE TABLE "TwoFactorAuthRecoveryKey" (
    "key" TEXT NOT NULL,
    "isUsed" BOOLEAN NOT NULL DEFAULT false,
    "usedAt" TIMESTAMP(3),
    "twoFactorAuthUserId" INTEGER NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "TwoFactorAuth_userId_key" ON "TwoFactorAuth"("userId");

-- CreateIndex
CREATE UNIQUE INDEX "TwoFactorAuthRecoveryKey_key_key" ON "TwoFactorAuthRecoveryKey"("key");

-- CreateIndex
CREATE UNIQUE INDEX "TwoFactorAuthRecoveryKey_twoFactorAuthUserId_key" ON "TwoFactorAuthRecoveryKey"("twoFactorAuthUserId");

-- AddForeignKey
ALTER TABLE "TwoFactorAuthRecoveryKey" ADD CONSTRAINT "TwoFactorAuthRecoveryKey_twoFactorAuthUserId_fkey" FOREIGN KEY ("twoFactorAuthUserId") REFERENCES "TwoFactorAuth"("userId") ON DELETE CASCADE ON UPDATE CASCADE;
