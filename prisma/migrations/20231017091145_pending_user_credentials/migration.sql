-- CreateTable
CREATE TABLE "PendingUserCredentials" (
    "userId" INTEGER NOT NULL,
    "password" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "PendingUserCredentials_userId_key" ON "PendingUserCredentials"("userId");
