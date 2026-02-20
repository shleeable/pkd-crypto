<?php
declare(strict_types=1);
namespace FediE2EE\PKD\Crypto\Tests;

use FediE2EE\PKD\Crypto\Exceptions\{
    CryptoException,
    NotImplementedException
};
use FediE2EE\PKD\Crypto\{
    Revocation,
    SecretKey
};
use ParagonIE\ConstantTime\Base64UrlSafe;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SodiumException;

#[CoversClass(Revocation::class)]
class RevocationTest extends TestCase
{
    /**
     * @return void
     * @throws CryptoException
     * @throws NotImplementedException
     * @throws SodiumException
     */
    public function testRevokeFlow(): void
    {
        $sk = SecretKey::generate();
        $pk = $sk->getPublicKey();

        $sk2 = SecretKey::generate();

        $revocation = new Revocation();
        $token = $revocation->revokeThirdParty($sk);
        $this->assertTrue($revocation->verifyRevocationToken($token));

        $token2 = $revocation->revokeThirdParty($sk2);
        $this->assertTrue($revocation->verifyRevocationToken($token2));

        $this->expectException(CryptoException::class);
        $revocation->verifyRevocationToken($token2, $pk);
    }

    /**
     * @throws CryptoException
     */
    public function testInvalidLength(): void
    {
        $revocation = new Revocation();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Token must be exactly 153 bytes');
        $revocation->decode(Base64UrlSafe::encodeUnpadded(str_repeat('a', 152)));
    }

    /**
     * @throws CryptoException
     */
    public function testInvalidLengthLong(): void
    {
        $revocation = new Revocation();
        $this->expectException(CryptoException::class);
        $this->expectExceptionMessage('Token must be exactly 153 bytes');
        $revocation->decode(Base64UrlSafe::encodeUnpadded(str_repeat('a', 154)));
    }
}
