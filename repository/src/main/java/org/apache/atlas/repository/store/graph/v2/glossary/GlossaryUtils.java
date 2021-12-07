package org.apache.atlas.repository.store.graph.v2.glossary;

import org.apache.atlas.util.NanoIdUtils;
import org.apache.commons.lang.StringUtils;

public class GlossaryUtils {


    private static final char[] invalidNameChars = {'@'};

    static final String ANCHOR            = "anchor";
    static final String CATEGORY_PARENT   = "parentCategory";
    static final String CATEGORY_CHILDREN = "childrenCategories";


    static String getUUID(){
        return NanoIdUtils.randomNanoId();
    }

    static boolean isNameInvalid(String name) {
        return StringUtils.containsAny(name, invalidNameChars);
    }
}
