/*
 * The MIT License
 * 
 * Copyright (c) 2004-2016, Sun Microsystems, Inc., Kohsuke Kawaguchi, Yahoo! Inc., Seiji Sogabe, Tom Huybrechts, Jochen Fuerbacher
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.security;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Set;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.servlet.ServletException;

import org.acegisecurity.acls.sid.Sid;
import org.jenkinsci.plugins.matrixauth.Messages;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.Stapler;
import org.kohsuke.stapler.StaplerRequest;

import com.thoughtworks.xstream.converters.Converter;
import com.thoughtworks.xstream.converters.MarshallingContext;
import com.thoughtworks.xstream.converters.UnmarshallingContext;
import com.thoughtworks.xstream.io.HierarchicalStreamReader;
import com.thoughtworks.xstream.io.HierarchicalStreamWriter;

import hudson.Extension;
import hudson.model.Item;
import hudson.model.Job;
import hudson.model.View;
import hudson.model.ViewProperty;
import hudson.model.ViewPropertyDescriptor;
import hudson.security.GlobalMatrixAuthorizationStrategy;
import hudson.security.Permission;
import hudson.security.PermissionGroup;
import hudson.security.PermissionScope;
import hudson.security.SidACL;
import hudson.util.FormValidation;
import hudson.util.RobustReflectionConverter;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject;

public class ViewAuthorizationMatrixProperty extends ViewProperty {
    
    private transient SidACL acl = new AclImpl();

    private final Map<Permission, Set<String>> grantedPermissions = new HashMap<Permission, Set<String>>();

    private Set<String> sids = new HashSet<String>();

    private boolean blocksInheritance = false;
    
    private static final Logger LOGGER = Logger.getLogger(ViewAuthorizationMatrixProperty.class.getName());

    private static final Pattern REFERER = Pattern.compile(".+?((/view/[^/]+)+)/configure");
       
    private ViewAuthorizationMatrixProperty() {
    }

    public ViewAuthorizationMatrixProperty(Map<Permission, Set<String>> grantedPermissions) {
        // do a deep copy to be safe
        for (Entry<Permission,Set<String>> e : grantedPermissions.entrySet())
            this.grantedPermissions.put(e.getKey(),new HashSet<String>(e.getValue()));
    }

    public Set<String> getGroups() {
        return sids;
    }
    
    public List<String> getAllSIDs() {
        Set<String> r = new HashSet<String>();
        for (Set<String> set : grantedPermissions.values())
            r.addAll(set);
        r.remove("anonymous");

        String[] data = r.toArray(new String[r.size()]);
        Arrays.sort(data);
        return Arrays.asList(data);
    }

    public Map<Permission,Set<String>> getGrantedPermissions() {
        return Collections.unmodifiableMap(grantedPermissions);
    }

    protected void add(Permission p, String sid) {
        Set<String> set = grantedPermissions.get(p);
        if (set == null)
            grantedPermissions.put(p, set = new HashSet<String>());
        set.add(sid);
        sids.add(sid);
    }
    
    
    
    @Extension
    public static class DescriptorImpl extends ViewPropertyDescriptor {
        
        @Override
        public String getDisplayName() {
            return Messages.ViewMatrixAuthorizationStrategy_DisplayName();
        }
        
        @Override
        public boolean isEnabledFor(View view) {
            // only enabled when ViewMatrixAuthorizationStrategy is in
            // charge
            return Jenkins.getInstanceOrNull()
                    .getAuthorizationStrategy() instanceof ViewMatrixAuthorizationStrategy;
        }
        
        @Override
        public ViewProperty newInstance(StaplerRequest req,
                JSONObject formData) throws FormException {

            ViewAuthorizationMatrixProperty amp = new ViewAuthorizationMatrixProperty();     
            
            // Disable inheritance, if so configured
            amp.setBlocksInheritance(!formData
                    .getJSONObject("blocksInheritance").isNullObject());

            Map<String, Object> data = formData.getJSONObject("data");
            for (Map.Entry<String, Object> r : data.entrySet()) {
                String sid = r.getKey();
                if (!(r.getValue() instanceof JSONObject)) {
                    throw new FormException("not an object: " + formData,
                            "data");
                }
                
                Map<String, Object> value = (JSONObject) r.getValue();
                for (Map.Entry<String, Object> e : value.entrySet()) {
                    if (!(e.getValue() instanceof Boolean)) {
                        throw new FormException("not a boolean: " + formData,
                                "data");
                    }
                    if ((Boolean) e.getValue()) {
                        
                        Permission p = Permission.fromId(e.getKey());
                        amp.add(p, sid);
                    }
                }
            }
            return amp;
        }

        public List<PermissionGroup> getAllGroups() {
            List<PermissionGroup> r = new ArrayList<PermissionGroup>();
            for (PermissionGroup pg : PermissionGroup.getAll()) {
                if (pg.hasPermissionContainedBy(PermissionScope.VIEW))
                    r.add(pg);
            }
            return r;
        }

        public boolean showPermission(Permission p) {
            return p.getEnabled() && p.isContainedBy(PermissionScope.VIEW);
        }

        public FormValidation doCheckName(@QueryParameter String value) throws IOException, ServletException {
                                                          
            View view = findViewFromRequest(View.class);
            return GlobalMatrixAuthorizationStrategy.DESCRIPTOR.doCheckName_(value, view, View.CONFIGURE);
        }
        
        static @CheckForNull String viewFromReferer(@Nonnull String referer) {
            Matcher m = REFERER.matcher(referer);
            if (m.matches()) {
                return URI.create(m.group(1).replace("/view/", "/")).getPath().substring(1);
            } else {
                return null;
            }
        }
        
        public static @CheckForNull <T extends View> T findViewFromRequest(Class<T> type) {
            StaplerRequest request = Stapler.getCurrentRequest();
            if (request == null) {
                LOGGER.warning("no current request");
                return null;
            }
            T ancestor = request.findAncestorObject(type);
            if (ancestor != null) {
                LOGGER.log(Level.FINE, "found {0} in {1}", new Object[] {ancestor, request.getRequestURI()});
                return ancestor;
            }
            String referer = request.getReferer();
            if (referer != null) {
                String name = viewFromReferer(referer);
                if (name != null) {
                    Jenkins jenkins = Jenkins.getInstance();
                    if (jenkins == null) {
                        LOGGER.warning("Jenkins is not running");
                        return null;
                    }
                    View view = jenkins.getView(name);
                    if (type.isInstance(view)) {
                        LOGGER.log(Level.FINE, "found {0} from {1}", new Object[] {view, referer});
                        return type.cast(view);
                    } else if (view != null) {
                        LOGGER.log(Level.FINE, "{0} was not a {1}", new Object[] {view, type.getName()});
                    } else {
                        LOGGER.log(Level.WARNING, "no such item {0}", name);
                    }
                } else {
                    LOGGER.log(request.findAncestorObject(Item.class) == null ? Level.WARNING : Level.FINE, "unrecognized Referer: {0} from {1}", new Object[] {referer, request.getRequestURI()});
                }
            } else {
                LOGGER.log(Level.WARNING, "no Referer in {0}", request.getRequestURI());
            }
            return null;
        }
        
    }
    
    private final class AclImpl extends SidACL {
        @CheckForNull
        protected Boolean hasPermission(Sid sid, Permission p) {
            if (ViewAuthorizationMatrixProperty.this.hasPermission(toString(sid),
                    p)) {
                return true;
            }
            return null;
        }
    }
    
    public SidACL getACL() {
        return acl;
    }

    private void setBlocksInheritance(boolean blocksInheritance) {
        this.blocksInheritance = blocksInheritance;
    }

    public boolean isBlocksInheritance() {
        return this.blocksInheritance;
    }
        
    public boolean hasPermission(String sid, Permission p) {
        for (; p != null; p = p.impliedBy) {
            Set<String> set = grantedPermissions.get(p);
            if (set != null && set.contains(sid))
                return true;
        }
        return false;
    }

    public boolean hasExplicitPermission(String sid, Permission p) {
        Set<String> set = grantedPermissions.get(p);
        return set != null && set.contains(sid);
    }

    private void add(String shortForm) {
        int idx = shortForm.indexOf(':');
        Permission p = Permission.fromId(shortForm.substring(0, idx));
        if (p == null)
            throw new IllegalArgumentException("Failed to parse '" + shortForm
                    + "' --- no such permission");
        add(p, shortForm.substring(idx + 1));
    }
    
    public static final class ConverterImpl implements Converter {
        public boolean canConvert(Class type) {
            return type == ViewAuthorizationMatrixProperty.class;
        }

        public void marshal(Object source, HierarchicalStreamWriter writer,
                MarshallingContext context) {
            ViewAuthorizationMatrixProperty amp = (ViewAuthorizationMatrixProperty) source;

            if (amp.isBlocksInheritance()) {
                writer.startNode("blocksInheritance");
                writer.setValue("true");
                writer.endNode();
            }

            for (Entry<Permission, Set<String>> e : amp.grantedPermissions
                    .entrySet()) {
                String p = e.getKey().getId();
                for (String sid : e.getValue()) {
                    writer.startNode("permission");
                    writer.setValue(p + ':' + sid);
                    writer.endNode();
                }
            }
        }

        public Object unmarshal(HierarchicalStreamReader reader,
                final UnmarshallingContext context) {
            ViewAuthorizationMatrixProperty as = new ViewAuthorizationMatrixProperty();

            String prop = reader.peekNextChild();
            
            if (prop != null && "blocksInheritance".equals(prop)) {
                reader.moveDown();
                as.setBlocksInheritance("true".equals(reader.getValue()));
                reader.moveUp();
            }
         
            while (reader.hasMoreChildren()) {
                reader.moveDown();
                try {
                    as.add(reader.getValue());
                } catch (IllegalArgumentException ex) {
                    Logger.getLogger(
                            ViewAuthorizationMatrixProperty.class.getName())
                            .log(Level.WARNING,
                                    "Skipping a non-existent permission", ex);
                    RobustReflectionConverter.addErrorInContext(context, ex);
                }
                reader.moveUp();
            }

            return as;
        }
    }    

}
