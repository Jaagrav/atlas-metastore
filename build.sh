#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

mkdir ~/.m2

wget https://atlan-build-artifacts.s3-ap-south-1.amazonaws.com/artifact/maven_local_repository.zip
unzip maven_local_repository.zip -d ~/.m2

echo "Maven Building"
mvn -T 100 -pl '!addons/hdfs-model,!addons/hive-bridge,!addons/hive-bridge-shim,!addons/falcon-bridge-shim,!addons/falcon-bridge,!addons/sqoop-bridge,!addons/sqoop-bridge-shim,!addons/hbase-bridge,!addons/hbase-bridge-shim' -Dmaven.test.skip -DskipTests -Drat.skip=true package -Pdist

echo "[DEBUG listing distro/target"
ls distro/target

echo "[DEBUG] listting local directory"
ls

