-- CreateTable
CREATE TABLE "UserCredentials" (
    "userId" INTEGER NOT NULL,
    "password" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "UserCredentials_userId_key" ON "UserCredentials"("userId");
