package oauthorize.hash

import oauthorize.model._
import oauthorize.utils._
import java.security.SecureRandom
import org.mindrot.jbcrypt.BCrypt

trait Hasher {
  def hashSecret(info: SecretInfo): String
  def secretMatches(rawPassword: String, info: SecretInfo): Boolean
}

class Sha256Hasher extends Hasher {
  override def hashSecret(info: SecretInfo): String = sha256(info.salt.getOrElse("") + info.secret)
  override def secretMatches(rawPassword: String, info: SecretInfo): Boolean = constantTimeEquals(sha256(info.salt.getOrElse("") + rawPassword), info.secret)
  private def constantTimeEquals(a: String, b: String) = {
    if (a.length != b.length) {
      false
    } else {
      var equal = 0
      for (i <- 0 until a.length) {
        equal |= a(i) ^ b(i)
      }
      equal == 0
    }
  }
}

class BCryptHasher(val rounds: Int) extends Hasher {
  private val rnd = new SecureRandom
  private def paddedRounds = { rounds.toString.reverse.padTo(2, "0").reverse.mkString }
  private def prefix = "$2a$" + paddedRounds + "$"
  override def hashSecret(info: SecretInfo): String = BCrypt.hashpw(info.secret, BCrypt.gensalt(rounds, rnd)).substring(7)
  override def secretMatches(rawPassword: String, info: SecretInfo): Boolean = {
    (for {
      raw <- Option(rawPassword)
      enc <- Option(info.secret)
    } yield {
      enc.length == (60 - prefix.length) && BCrypt.checkpw(rawPassword, prefix + info.secret)
    }) getOrElse (false)
  }
}