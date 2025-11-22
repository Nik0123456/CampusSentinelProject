DROP SCHEMA IF EXISTS `mydb`;
CREATE SCHEMA IF NOT EXISTS `mydb` DEFAULT CHARACTER SET utf8;
USE `mydb`;

-- Tabla User
CREATE TABLE `User` (
  `idUser` INT NOT NULL AUTO_INCREMENT,
  `username` VARCHAR(100) NOT NULL,
  `current_ip` VARCHAR(45) NULL,
  `current_mac` VARCHAR(45) NULL,
  `current_in_port` INT NULL,
  `current_dpid` VARCHAR(45) NULL,
  `session_active` BOOLEAN NOT NULL DEFAULT FALSE,
  `session_token` VARCHAR(100) NULL,
  `session_expiry` DATETIME NULL,
  `flow_name` VARCHAR(255) NULL,
  `is_guest` BOOLEAN NULL DEFAULT FALSE,
  PRIMARY KEY (`idUser`),
  UNIQUE INDEX `username_UNIQUE` (`username` ASC)
) ENGINE = InnoDB;

-- Tabla Attribute
CREATE TABLE `Attribute` (
  `idAttribute` INT NOT NULL AUTO_INCREMENT,
  `name` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`idAttribute`)
) ENGINE = InnoDB;

-- Tabla AttributeValue
CREATE TABLE `AttributeValue` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `value` VARCHAR(100) NOT NULL,
  `attribute_id` INT NOT NULL,
  PRIMARY KEY (`id`),
  INDEX `fk_AttributeValue_Attribute_idx` (`attribute_id` ASC),
  CONSTRAINT `fk_AttributeValue_Attribute`
    FOREIGN KEY (`attribute_id`)
    REFERENCES `Attribute` (`idAttribute`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE = InnoDB;

-- Tabla User_has_AttributeValue
CREATE TABLE `User_has_AttributeValue` (
  `user_id` INT NOT NULL,
  `attributevalue_id` INT NOT NULL,
  PRIMARY KEY (`user_id`, `attributevalue_id`),
  INDEX `fk_User_has_AttributeValue_AttributeValue1_idx` (`attributevalue_id` ASC),
  INDEX `fk_User_has_AttributeValue_User1_idx` (`user_id` ASC),
  CONSTRAINT `fk_User_has_AttributeValue_User1`
    FOREIGN KEY (`user_id`)
    REFERENCES `User` (`idUser`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `fk_User_has_AttributeValue_AttributeValue1`
    FOREIGN KEY (`attributevalue_id`)
    REFERENCES `AttributeValue` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE = InnoDB;

-- Tabla Permission
CREATE TABLE `Permission` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `serviceName` VARCHAR(100) NOT NULL,
  `serviceIP` VARCHAR(45) NOT NULL,
  `serviceMAC` VARCHAR(45) NULL,
  `serviceProtocol` VARCHAR(10) NOT NULL,
  `servicePort` VARCHAR(10) NOT NULL,
  `attributevalue_id` INT NOT NULL,
  `counter1` BIGINT NOT NULL DEFAULT 0,
  `counter2` BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (`id`),
  INDEX `fk_Permission_AttributeValue1_idx` (`attributevalue_id` ASC),
  CONSTRAINT `fk_Permission_AttributeValue1`
    FOREIGN KEY (`attributevalue_id`)
    REFERENCES `AttributeValue` (`id`)
    ON DELETE NO ACTION
    ON UPDATE NO ACTION
) ENGINE = InnoDB;

