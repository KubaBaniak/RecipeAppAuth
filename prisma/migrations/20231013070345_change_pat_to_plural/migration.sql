/*
  Warnings:

  - You are about to drop the `PersonalAccessToken` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropTable
DROP TABLE "PersonalAccessToken";

-- CreateTable
CREATE TABLE "PersonalAccessTokens" (
    "userId" INTEGER NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "token" TEXT NOT NULL,
    "invalidatedAt" TIMESTAMP(3)
);

-- CreateIndex
CREATE UNIQUE INDEX "PersonalAccessTokens_userId_key" ON "PersonalAccessTokens"("userId");
