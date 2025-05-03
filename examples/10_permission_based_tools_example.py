"""
This example shows how to filter tools based on user permissions.

It demonstrates how to use the tool_visibility_callback parameter to determine
which tools are visible based on the user's permissions.
"""
from typing import Dict, Any, List, Union, Optional
from pydantic import BaseModel, Field

from fastapi import FastAPI, Depends, HTTPException, Path, Request, status
from fastapi.security import OAuth2PasswordBearer

from examples.shared.setup import setup_logging
from fastapi_mcp import FastApiMCP, ToolVisibilityCallback

setup_logging()

app = FastAPI(title="Permission-Based Tools Example")

PRODUCT_VIEW = "product:view"
PRODUCT_CREATE = "product:create"
PRODUCT_UPDATE = "product:update"
PRODUCT_DELETE = "product:delete"
FINGERPRINT_VIEW = "fingerprint:view"

class User(BaseModel):
    id: int
    username: str
    permissions: List[str] = []

USERS = {
    "admin": User(id=1, username="admin", permissions=[
        PRODUCT_VIEW, PRODUCT_CREATE, PRODUCT_UPDATE, PRODUCT_DELETE, FINGERPRINT_VIEW
    ]),
    "viewer": User(id=2, username="viewer", permissions=[
        PRODUCT_VIEW, FINGERPRINT_VIEW
    ]),
    "editor": User(id=3, username="editor", permissions=[
        PRODUCT_VIEW, PRODUCT_CREATE, PRODUCT_UPDATE
    ]),
}

class BaseResponse(BaseModel):
    code: int = 200
    message: str = "Success"
    data: Any = None

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: str = Depends(oauth2_scheme)) -> Optional[User]:
    if token in USERS:
        return USERS[token]
    return None

class PermissionChecker:
    """权限检查类依赖项，支持单个权限代码或权限代码列表"""
    
    def __init__(self, permission_code: Union[str, List[str]]):
        """初始化权限检查器
        
        Args:
            permission_code: 权限代码或权限代码列表，如果是列表，则用户拥有其中任意一个权限即可通过验证
        """
        self.permission_code = permission_code if isinstance(permission_code, list) else [permission_code]
    
    async def __call__(self, user: User = Depends(get_current_user)):
        """检查用户是否具有指定权限"""
        if not user:
            response = BaseResponse(
                code=401,
                message="未登录或会话已过期"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={"baseResponse": response.dict()}
            )
        
        has_permission = any(perm in user.permissions for perm in self.permission_code)
        
        if not has_permission:
            response = BaseResponse(
                code=403,
                message=f"没有所需权限: {', '.join(self.permission_code)}"
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={"baseResponse": response.dict()}
            )
        return user

@app.get(
    "/products",
    response_model=BaseResponse,
    summary="获取产品列表",
    description="获取所有产品的列表",
    operation_id="list_products",
    dependencies=[Depends(PermissionChecker(PRODUCT_VIEW))]
)
async def list_products(user: User = Depends(get_current_user)):
    return BaseResponse(data=[{"id": 1, "name": "Product 1"}, {"id": 2, "name": "Product 2"}])

@app.get(
    "/products/{product_id}",
    response_model=BaseResponse,
    summary="获取产品详情",
    description="根据产品ID获取产品的详细信息",
    operation_id="get_product",
    dependencies=[Depends(PermissionChecker(PRODUCT_VIEW))]
)
async def get_product(
    product_id: int = Path(..., title="产品ID", description="要获取的产品ID"),
    user: User = Depends(get_current_user)
):
    return BaseResponse(data={"id": product_id, "name": f"Product {product_id}"})

@app.post(
    "/products",
    response_model=BaseResponse,
    summary="创建产品",
    description="创建一个新的产品",
    operation_id="create_product",
    dependencies=[Depends(PermissionChecker(PRODUCT_CREATE))]
)
async def create_product(user: User = Depends(get_current_user)):
    return BaseResponse(message="产品创建成功", data={"id": 3, "name": "New Product"})

@app.put(
    "/products/{product_id}",
    response_model=BaseResponse,
    summary="更新产品",
    description="根据产品ID更新产品信息",
    operation_id="update_product",
    dependencies=[Depends(PermissionChecker(PRODUCT_UPDATE))]
)
async def update_product(
    product_id: int = Path(..., title="产品ID", description="要更新的产品ID"),
    user: User = Depends(get_current_user)
):
    return BaseResponse(message="产品更新成功", data={"id": product_id, "name": f"Updated Product {product_id}"})

@app.delete(
    "/products/{product_id}",
    response_model=BaseResponse,
    summary="删除产品",
    description="根据产品ID删除产品",
    operation_id="delete_product",
    dependencies=[Depends(PermissionChecker(PRODUCT_DELETE))]
)
async def delete_product(
    product_id: int = Path(..., title="产品ID", description="要删除的产品ID"),
    user: User = Depends(get_current_user)
):
    return BaseResponse(message="产品删除成功")

@app.get(
    "/fingerprint/{product_id}",
    response_model=BaseResponse,
    summary="获取产品指纹",
    description="根据产品ID获取产品的指纹信息",
    operation_id="get_fingerprint",
    dependencies=[Depends(PermissionChecker(FINGERPRINT_VIEW))],
)
async def get_fingerprint(
    product_id: int = Path(..., title="产品ID", description="要获取指纹的产品ID"),
    user: User = Depends(get_current_user),
):
    return BaseResponse(data={"product_id": product_id, "fingerprint": f"FP-{product_id}-XXXX"})

async def get_request_user(request: Request):
    """尝试从请求中获取当前用户"""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        if token in USERS:
            return USERS[token]
    return None

def permission_based_tool_visibility(operation_id: str, operation_details: Dict[str, Any]) -> bool:
    """
    基于操作的权限要求确定工具可见性
    
    Args:
        operation_id: 操作ID
        operation_details: 操作详情
        
    Returns:
        如果用户有权限查看该工具，则返回True，否则返回False
    """
    operation = operation_details.get("operation", {})
    dependencies = operation.get("dependencies", [])
    
    required_permissions = []
    for dep in dependencies:
        if "PermissionChecker" in str(dep):
            if operation_id == "list_products" or operation_id == "get_product":
                required_permissions.append(PRODUCT_VIEW)
            elif operation_id == "create_product":
                required_permissions.append(PRODUCT_CREATE)
            elif operation_id == "update_product":
                required_permissions.append(PRODUCT_UPDATE)
            elif operation_id == "delete_product":
                required_permissions.append(PRODUCT_DELETE)
            elif operation_id == "get_fingerprint":
                required_permissions.append(FINGERPRINT_VIEW)
    
    if not required_permissions:
        return True
    
    def check_permissions(user: Optional[User] = None) -> bool:
        if not user:
            return False
        return any(perm in user.permissions for perm in required_permissions)
    
    return check_permissions

mcp = FastApiMCP(
    app,
    name="Permission-Based Tools Example",
    tool_visibility_callback=permission_based_tool_visibility,
)

mcp.mount()

if __name__ == "__main__":
    import uvicorn
    
    print("启动示例服务器...")
    print("你可以使用以下用户名作为令牌进行测试:")
    print(" - admin: 拥有所有权限")
    print(" - viewer: 只有查看权限")
    print(" - editor: 拥有创建和更新权限")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)
