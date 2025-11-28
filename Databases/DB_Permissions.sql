DROP SCHEMA IF EXISTS `DB_Permissions`;
CREATE SCHEMA IF NOT EXISTS `DB_Permissions` DEFAULT CHARACTER SET utf8;
USE `DB_Permissions`;

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
  `serviceDPID` VARCHAR(23) NULL,
  `serviceInPort` INT NULL,
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

-- Tabla muchos a muchos: User_Permission_Usage
-- Esta tabla registra el uso de permisos por cada usuario para análisis de patrones
CREATE TABLE `User_Permission_Usage` (
  `user_id` INT NOT NULL,
  `permission_id` INT NOT NULL,
  `usage_count` BIGINT NOT NULL DEFAULT 0,
  `last_used` DATETIME NULL,
  `avg_session_duration` INT NULL COMMENT 'Duración promedio en segundos',
  PRIMARY KEY (`user_id`, `permission_id`),
  INDEX `fk_User_Permission_Usage_User_idx` (`user_id` ASC),
  INDEX `fk_User_Permission_Usage_Permission_idx` (`permission_id` ASC),
  INDEX `idx_usage_count` (`usage_count` DESC),
  CONSTRAINT `fk_User_Permission_Usage_User`
    FOREIGN KEY (`user_id`)
    REFERENCES `User` (`idUser`)
    ON DELETE CASCADE
    ON UPDATE CASCADE,
  CONSTRAINT `fk_User_Permission_Usage_Permission`
    FOREIGN KEY (`permission_id`)
    REFERENCES `Permission` (`id`)
    ON DELETE CASCADE
    ON UPDATE CASCADE
) ENGINE = InnoDB
COMMENT = 'Tabla para tracking de uso de permisos por usuario - permite carga proactiva';

-- ========================================
-- EVENTO: Limpieza automática de sesiones expiradas
-- ========================================
DELIMITER $$

CREATE EVENT IF NOT EXISTS `cleanup_expired_sessions`
ON SCHEDULE EVERY 5 MINUTE
STARTS CURRENT_TIMESTAMP
DO
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE v_user_id INT;
    DECLARE v_is_guest BOOLEAN;
    DECLARE cur CURSOR FOR 
        SELECT idUser, is_guest 
        FROM User 
        WHERE session_active = 1 
          AND session_expiry < NOW();
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;

    OPEN cur;

    read_loop: LOOP
        FETCH cur INTO v_user_id, v_is_guest;
        IF done THEN
            LEAVE read_loop;
        END IF;

        IF v_is_guest = 1 THEN
            -- Usuario invitado: eliminar sus atributos y luego el usuario
            DELETE FROM User_has_AttributeValue WHERE user_id = v_user_id;
            DELETE FROM User_Permission_Usage WHERE user_id = v_user_id;
            DELETE FROM User WHERE idUser = v_user_id;
        ELSE
            -- Usuario regular: solo desactivar sesión
            UPDATE User 
            SET session_active = 0,
                session_token = NULL,
                session_expiry = NULL
            WHERE idUser = v_user_id;
        END IF;
    END LOOP;

    CLOSE cur;
END$$

DELIMITER ;

-- Habilitar el event scheduler si no está activo
SET GLOBAL event_scheduler = ON;

