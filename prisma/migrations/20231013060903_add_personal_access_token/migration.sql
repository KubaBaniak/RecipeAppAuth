-- CreateTable
CREATE TABLE "PersonalAccessToken" (
    "userId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "token" TEXT NOT NULL,
    "invalidatedAt" TIMESTAMP(3)
);

-- CreateIndex
CREATE UNIQUE INDEX "PersonalAccessToken_userId_key" ON "PersonalAccessToken"("userId");
