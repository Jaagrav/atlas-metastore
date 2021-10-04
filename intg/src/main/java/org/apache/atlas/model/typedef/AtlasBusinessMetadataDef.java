/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.atlas.model.typedef;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.apache.atlas.model.TypeCategory;
import org.apache.commons.lang3.RandomStringUtils;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;
import java.util.List;
import java.util.Map;

import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.NONE;
import static com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.PUBLIC_ONLY;

@JsonAutoDetect(getterVisibility=PUBLIC_ONLY, setterVisibility=PUBLIC_ONLY, fieldVisibility=NONE)
@JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown=true)
@XmlRootElement
@XmlAccessorType(XmlAccessType.PROPERTY)
public class AtlasBusinessMetadataDef extends AtlasStructDef implements Serializable {
    private static final long serialVersionUID = 1L;

    public static final String ATTR_OPTION_APPLICABLE_ENTITY_TYPES = "applicableEntityTypes";
    public static final String ATTR_MAX_STRING_LENGTH              = "maxStrLength";
    public static final String ATTR_VALID_PATTERN                  = "validPattern";

    private String displayName;

    public AtlasBusinessMetadataDef() {
        this(null, null, null, null);
    }

    public AtlasBusinessMetadataDef(String displayName, String description) {
        this(displayName, description, null, null, null);
    }

    public AtlasBusinessMetadataDef(String displayName, String description, String typeVersion) {
        this(displayName, description, typeVersion, null, null);
    }

    public AtlasBusinessMetadataDef(String displayName, String description, String typeVersion, List<AtlasAttributeDef> attributeDefs) {
        this(displayName, description, typeVersion, attributeDefs, null);
    }

    public AtlasBusinessMetadataDef(String displayName, String description, String typeVersion, List<AtlasAttributeDef> attributeDefs, Map<String, String> options) {
        this(generateRandomName(), displayName, description, typeVersion, attributeDefs, options);
    }
    public AtlasBusinessMetadataDef(String name, String displayName, String description, String typeVersion, List<AtlasAttributeDef> attributeDefs, Map<String, String> options) {
        super(TypeCategory.BUSINESS_METADATA, name, description, typeVersion, attributeDefs, options);
        this.displayName = displayName;
    }
    public AtlasBusinessMetadataDef(AtlasBusinessMetadataDef other) {
        super(other);
    }

    @Override
    protected void appendExtraBaseTypeDefToString(StringBuilder sb) {
        super.appendExtraBaseTypeDefToString(sb);
        sb.append(", displayName='").append(this.displayName).append('\'');
    }

    @Override
    public String toString() {
        return toString(new StringBuilder()).toString();
    }

    @Override
    public StringBuilder toString(StringBuilder sb) {
        if (sb == null) {
            sb = new StringBuilder();
        }

        sb.append("AtlasBusinessMetadataDef{");
        super.toString(sb);
        sb.append('}');

        return sb;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public void setRandomNameForEntityAndAttributeDefs() {
        setName(generateRandomName());
        this.getAttributeDefs().forEach((attr) -> attr.setName(generateRandomName()));
    }

    public static String generateRandomName() {
        return RandomStringUtils.randomAlphabetic(1) + RandomStringUtils.randomAlphanumeric(21);
    }

    @Override
    public int hashCode() {
        return (this.displayName == null ? 0 : this.displayName.hashCode()) + super.hashCode() * 31;
    }

    @Override
    protected String getAttributeUniqueField(AtlasAttributeDef attribute) {
        return attribute != null ? attribute.getDisplayName() : null;
    }
}