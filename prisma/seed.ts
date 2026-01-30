import 'dotenv/config';
import { PrismaPg } from '@prisma/adapter-pg';
import { PrismaClient } from '../src/generated/prisma/client';
import * as bcrypt from 'bcrypt';

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL!,
});

const prisma = new PrismaClient({ adapter });

async function main() {
  console.log('Starting database seed...');

  console.log('Seeding roles...');
  await prisma.role.createMany({
    data: [
      { name: 'user' },
      { name: 'admin' },
      { name: 'moderator' },
    ],
    skipDuplicates: true,
  });

  console.log('Seeding admin user...');
  const adminEmail = 'admin@example.com';
  const existingAdmin = await prisma.user.findUnique({
    where: { email: adminEmail },
  });

  if (!existingAdmin) {
    const hashedPassword = await bcrypt.hash('AdminPass1234', 12);
    const adminRole = await prisma.role.findUnique({
      where: { name: 'admin' },
    });

    await prisma.user.create({
      data: {
        email: adminEmail,
        password: hashedPassword,
        isVerified: true,
        isActive: true,
        roles: {
          create: [
            { roleId: adminRole!.id },
          ],
        },
      },
    });
  } 

  if (process.env.NODE_ENV === 'development') {
    const userRole = await prisma.role.findUnique({
      where: { name: 'user' },
    });

    const testUsers = [
      { email: 'user1@example.com', password: 'UserPass1234' },
      { email: 'user2@example.com', password: 'UserPass1234' },
    ];

    for (const testUser of testUsers) {
      const existing = await prisma.user.findUnique({
        where: { email: testUser.email },
      });

      if (!existing) {
        const hashedPassword = await bcrypt.hash(testUser.password, 12);
        await prisma.user.create({
          data: {
            email: testUser.email,
            password: hashedPassword,
            isVerified: false,
            isActive: true,
            roles: {
              create: [{ roleId: userRole!.id }],
            },
          },
        });
      }
    }
  }

  console.log('Seed completed successfully!');
}

main()
  .catch((e) => {
    console.error('Seed failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });